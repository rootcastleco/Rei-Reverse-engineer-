"""Local, append-only SHA-256 event chain for investigation provenance."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Iterator

from .inspector import inspect_path


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        with tmp.open("x", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    lock = path / ".write.lock"
    fd: int | None = None
    start = time.monotonic()
    while fd is None:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"pid={os.getpid()} created={_now()}\n".encode())
        except FileExistsError:
            if time.monotonic() - start > 4:
                raise TimeoutError(f"Case is locked: {lock}; check for stale writer before removal")
            time.sleep(.05)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        lock.unlink(missing_ok=True)


def create_case(target: str | Path, workspace: str | Path = ".rei-cases") -> dict:
    inspection = inspect_path(target)
    folder = Path(workspace).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^a-z0-9-]+", "-", Path(inspection["path"]).stem.lower()).strip("-")[:35] or "target"
    prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_id = f"{prefix}-{name}-{inspection['sha256'][:12]}"
    case_path = folder / base_id
    suffix = 0
    while True:
        try:
            case_path.mkdir(mode=0o700)
            break
        except FileExistsError:
            suffix += 1
            case_path = folder / f"{base_id}-{suffix}"
    manifest = {"schema_version": 1, "case_id": case_path.name, "created_utc": _now(),
                "target": inspection, "notice": "Local metadata, no automatic uploading. Artifact content is not copied."}
    _atomic_json(case_path / "case.json", manifest)
    (case_path / "events.jsonl").touch(mode=0o600)
    append_event(case_path, "target-inspected", {"sha256": inspection["sha256"], "kind": inspection["kind"],
                                                "identity_complete": inspection["identity_complete"]}, confidence="observed")
    return {"case_path": str(case_path), "case_id": case_path.name, "target": inspection}


def append_event(case_path: str | Path, event_type: str, payload: dict, *, confidence: str = "observed") -> dict:
    case = Path(case_path).resolve(strict=True)
    if confidence not in ("observed", "inferred", "unknown"):
        raise ValueError("confidence must be observed, inferred or unknown")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", event_type):
        raise ValueError("event type must be lowercase kebab case")
    if not (case / "case.json").exists():
        raise ValueError("Not a REI REA case")
    with _lock(case):
        check = verify_case(case)
        if not check["valid"]:
            raise ValueError(f"Evidence chain invalid: {check['errors']}")
        seq = check["event_count"] + 1
        entry = {"seq": seq, "utc": _now(), "type": event_type, "confidence": confidence,
                 "payload": payload, "previous_hash": check["tail_hash"]}
        entry["record_hash"] = sha256(canonical(entry))
        with (case / "events.jsonl").open("ab") as f:
            f.write(canonical(entry) + b"\n")
            f.flush()
            os.fsync(f.fileno())
    return entry


def verify_case(case_path: str | Path, *, recheck_target: bool = False) -> dict:
    case = Path(case_path).resolve(strict=True)
    errors: list[str] = []
    try:
        manifest = json.loads((case / "case.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"valid": False, "errors": [f"Invalid/missing manifest: {exc}"], "event_count": 0, "tail_hash": "0" * 64}
    if manifest.get("schema_version") != 1:
        errors.append("Unknown manifest version")
    prev, count = "0" * 64, 0
    try:
        with (case / "events.jsonl").open("rb") as f:
            for number, line in enumerate(f, 1):
                try:
                    row = json.loads(line)
                    saved_hash = row.pop("record_hash")
                    if row.get("seq") != number or row.get("previous_hash") != prev:
                        errors.append(f"Sequence/previous-hash mismatch on event {number}")
                    if sha256(canonical(row)) != saved_hash:
                        errors.append(f"Record hash mismatch on event {number}")
                    prev = saved_hash
                    count += 1
                except (ValueError, TypeError, KeyError, AttributeError):
                    errors.append(f"Malformed JSON evidence event at line {number}")
                    break
    except OSError as exc:
        errors.append(f"Could not read event chain: {exc}")
    if recheck_target:
        try:
            new = inspect_path(manifest["target"]["path"])
            if new["sha256"] != manifest["target"]["sha256"] or new["identity_complete"] != manifest["target"]["identity_complete"]:
                errors.append("Current target identity differs from case manifest")
        except (ValueError, OSError, KeyError) as exc:
            errors.append(f"Target recheck failed: {exc}")
    return {"valid": not errors, "errors": errors, "event_count": count, "tail_hash": prev,
            "target_sha256": manifest.get("target", {}).get("sha256"), "case_id": manifest.get("case_id")}


def render_report(case_path: str | Path) -> str:
    case = Path(case_path).resolve(strict=True)
    manifest = json.loads((case / "case.json").read_text(encoding="utf-8"))
    verification = verify_case(case)
    t = manifest["target"]
    lines = [f"# REI REA Investigation: {manifest['case_id']}", "", "## Artifact identity", "",
             f"- Target: `{t['path']}`", f"- Format: `{t['kind']}`", f"- SHA-256: `{t['sha256']}`",
             f"- Identity complete: `{t['identity_complete']}`", f"- Inspection method: {t['method']}",
             "", "## Evidence integrity", "", f"- Valid hash chain: **{verification['valid']}**",
             f"- Event count: {verification['event_count']}", f"- Tail SHA-256: `{verification['tail_hash']}`",
             "", "## Findings", "", "The current stage records artifact identity and static format observations only.",
             "No code behavior, feature parity, vulnerability, or execution safety has been established.", "",
             "## Verification limits", ""]
    lines.extend(f"- {w}" for w in t["warnings"])
    lines.extend(f"- {e}" for e in verification["errors"])
    if not t["warnings"] and not verification["errors"]:
        lines.append("- No structural warnings raised by the bounded inspector.")
    return "\n".join(lines) + "\n"
