"""Local, opt-in SQLite case index and portable metadata-only case bundles.

No target bytes, event payloads or raw strings enter the index. The event chain
is only tamper-evident against accidental changes, not a digital signature.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

from .evidence import render_report, verify_case

INDEX = ".rei-rea-casebook.sqlite3"
MAX_CASES = 5000
MAX_BUNDLE_BYTES = 32 * 1024 * 1024


def _workspace(path: str | Path) -> Path:
    p = Path(path).expanduser()
    if p.is_symlink():
        raise ValueError("Symlink workspaces are not permitted")
    p = p.resolve(strict=True)
    if not p.is_dir():
        raise ValueError("Workspace must be a directory")
    return p


def _open_index(workspace: Path, *, create: bool) -> sqlite3.Connection:
    index = workspace / INDEX
    if index.is_symlink():
        raise ValueError("Symlink SQLite index is not permitted")
    if not create and not index.is_file():
        raise FileNotFoundError("Case index missing; explicitly run `rei-rea case index WORKSPACE` first")
    con = sqlite3.connect(str(index) if create else f"file:{index.as_posix()}?mode=ro", uri=not create, timeout=8)
    if create:
        con.execute("""CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY, path TEXT NOT NULL, created_utc TEXT,
            artifact_sha256 TEXT NOT NULL, kind TEXT NOT NULL, event_count INTEGER NOT NULL,
            tail_hash TEXT NOT NULL, chain_valid INTEGER NOT NULL, indexed_utc TEXT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cases_kind ON cases(kind)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cases_sha ON cases(artifact_sha256)")
    return con


def index_cases(workspace: str | Path) -> dict:
    root = _workspace(workspace)
    discovered = sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and (p / "case.json").is_file())
    if len(discovered) > MAX_CASES:
        raise ValueError("Too many cases for bounded indexing")
    indexed = []
    skipped = []
    for case in discovered:
        if (case / "case.json").is_symlink() or (case / "events.jsonl").is_symlink():
            skipped.append({"case": case.name, "reason": "symlink evidence file"})
            continue
        try:
            manifest = json.loads((case / "case.json").read_text(encoding="utf-8"))
            verified = verify_case(case)
            target = manifest["target"]
            if manifest["case_id"] != case.name:
                raise ValueError("case_id does not match the case directory")
            if not isinstance(target["sha256"], str) or len(target["sha256"]) != 64:
                raise ValueError("invalid target sha256")
            indexed.append((case.name, str(case), manifest.get("created_utc", ""), target["sha256"],
                            target["kind"], verified["event_count"], verified["tail_hash"], int(verified["valid"]),
                            datetime.now(timezone.utc).isoformat(timespec="seconds")))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            skipped.append({"case": case.name, "reason": f"{type(exc).__name__}: {exc}"})
    with closing(_open_index(root, create=True)) as con, con:
        con.execute("DELETE FROM cases")
        con.executemany("INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", indexed)
    return {"workspace": str(root), "indexed": len(indexed), "valid": sum(bool(r[7]) for r in indexed),
            "invalid": sum(not bool(r[7]) for r in indexed), "skipped": skipped,
            "notice": "Explicit point-in-time index; re-run after cases change. Indexed metadata does not prove external authenticity."}


def search_cases(workspace: str | Path, *, query: str = "", kind: str = "", limit: int = 25) -> dict:
    if not 1 <= limit <= 100:
        raise ValueError("Search limit must be between 1 and 100")
    if len(query) > 256 or len(kind) > 64:
        raise ValueError("Search filters exceed length limits")
    root = _workspace(workspace)
    with closing(_open_index(root, create=False)) as con:
        con.row_factory = sqlite3.Row
        filters = []
        params: list = []
        if query:
            filters.append("(instr(lower(case_id), lower(?)) > 0 OR instr(lower(artifact_sha256), lower(?)) > 0)")
            params.extend((query, query))
        if kind:
            filters.append("kind = ?")
            params.append(kind)
        where = (" WHERE " + " AND ".join(filters)) if filters else ""
        total = con.execute("SELECT COUNT(*) FROM cases" + where, params).fetchone()[0]
        results = [dict(row) for row in con.execute("SELECT * FROM cases" + where + " ORDER BY created_utc DESC, case_id DESC LIMIT ?", [*params, limit])]
    return {"workspace": str(root), "total_matches": total, "results": results,
            "note": "Casebook is a snapshot. Verify the selected case again before acting on its evidence."}


def bundle_case(case_path: str | Path, output: str | Path) -> dict:
    case = Path(case_path).expanduser()
    if case.is_symlink():
        raise ValueError("Symlink cases are not supported")
    case = case.resolve(strict=True)
    validation = verify_case(case)
    if not validation["valid"]:
        raise ValueError("Cannot export a case with an invalid evidence chain")
    parts = {}
    for name in ("case.json", "events.jsonl"):
        path = case / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError(f"Unsafe or oversized case component: {name}")
        parts[name] = path.read_bytes()
    parts["report.md"] = render_report(case).encode("utf-8")
    record = {"schema_version": 1, "case_id": validation["case_id"], "tail_hash": validation["tail_hash"],
              "artifact_included": False, "files": {n: hashlib.sha256(data).hexdigest() for n, data in parts.items()},
              "notice": "Local SHA-256 integrity checks only; not cryptographically signed or independently timestamped."}
    parts["bundle-manifest.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    path = Path(output).expanduser()
    if path.is_symlink():
        raise ValueError("Symlink output is not permitted")
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as z:
        for name, data in sorted(parts.items()):
            z.writestr(name, data)
    return {"path": str(path.resolve()), "case_id": validation["case_id"],
            "archive_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "target_bytes_included": False, "entries": sorted(parts)}


def verify_bundle(path: str | Path) -> dict:
    p = Path(path).expanduser()
    if p.is_symlink():
        raise ValueError("Symlink bundle is not permitted")
    with zipfile.ZipFile(p.resolve(strict=True)) as z:
        items = z.infolist()
        if len(items) != 4 or {x.filename for x in items} != {"case.json", "events.jsonl", "report.md", "bundle-manifest.json"}:
            return {"valid": False, "reason": "Unexpected or duplicate archive members"}
        if any(x.file_size > MAX_BUNDLE_BYTES or x.compress_size > MAX_BUNDLE_BYTES for x in items):
            return {"valid": False, "reason": "Member exceeds verification budget"}
        record = json.loads(z.read("bundle-manifest.json"))
        matched = all(hashlib.sha256(z.read(name)).hexdigest() == digest for name, digest in record.get("files", {}).items()
                      if name in {"case.json", "events.jsonl", "report.md"})
        matched = matched and set(record.get("files", {})) == {"case.json", "events.jsonl", "report.md"}
        return {"valid": bool(matched), "case_id": record.get("case_id"), "tail_hash": record.get("tail_hash"),
                "limitations": "Checksums are inside the bundle and are not a signature or independent authenticity proof."}
