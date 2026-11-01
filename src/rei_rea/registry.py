"""Central tool registry: discovery does not imply installation or integration."""
from __future__ import annotations

import hashlib
import json
import os
from importlib import resources
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
from .discovery import resolve_executables


# Fixed, read-only command templates. This mapping is code-owned, not registry-provided.
# Never use a shell or accept user-provided command-line flags.
STATIC_ADAPTERS = {
    "file": ("file", "-b", "{target}"),
    "readelf": ("readelf", "-h", "{target}"),
    "objdump": ("objdump", "-f", "{target}"),
    "llvm-objdump": ("llvm-objdump", "-f", "{target}"),
    "llvm-readobj": ("llvm-readobj", "--file-headers", "{target}"),
    "nm": ("nm", "--defined-only", "{target}"),
    "exiftool": ("exiftool", "-j", "{target}"),
    "otool": ("otool", "-h", "{target}"),
    "android-aapt2": ("aapt2", "dump", "badging", "{target}"),
    "radare2": ("rabin2", "-I", "{target}"),
    "rizin": ("rz-bin", "-I", "{target}"),
}


class RegistryError(ValueError):
    """Invalid tool registry, selection or execution request."""


def load_catalog() -> list[dict]:
    data = json.loads(resources.files("rei_rea").joinpath("data/tools.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise RegistryError("Unsupported tool registry schema")
    result = data.get("tools")
    if not isinstance(result, list):
        raise RegistryError("Missing tool list")
    seen: set[str] = set()
    for tool in result:
        if not isinstance(tool, dict) or not isinstance(tool.get("id"), str):
            raise RegistryError("Malformed tool row")
        ident = tool["id"]
        if ident in seen or not ident.isascii() or not all(c.islower() or c.isdigit() or c == "-" for c in ident):
            raise RegistryError(f"Invalid/duplicate tool id: {ident!r}")
        if not isinstance(tool.get("executables"), list) or not tool["executables"]:
            raise RegistryError(f"Missing probes for tool: {ident}")
        if not isinstance(tool.get("tags"), list) or not isinstance(tool.get("homepage"), str):
            raise RegistryError(f"Bad metadata for tool: {ident}")
        if tool.get("integration") not in ("static-adapter", "discovery-only"):
            raise RegistryError(f"Bad integration mode: {ident}")
        if (tool["integration"] == "static-adapter") != (ident in STATIC_ADAPTERS):
            raise RegistryError(f"Catalog/adapter disagreement: {ident}")
        seen.add(ident)
    return result


def list_tools(*, tag: str | None = None, installed_only: bool = False) -> list[dict]:
    items = []
    catalog = [item for item in load_catalog()
               if not tag or tag in item["tags"] or tag == item["category"]]
    detected = resolve_executables(exe for item in catalog for exe in item["executables"])
    for item in catalog:
        found = next((detected[exe] for exe in item["executables"] if detected[exe]), None)
        adapter_exe = STATIC_ADAPTERS.get(item["id"], (None,))[0]
        adapter_path = detected.get(adapter_exe)
        if installed_only and not found:
            continue
        items.append({**item, "installed": bool(found), "resolved_executable": found,
                      "adapter_available": bool(adapter_path), "adapter_executable": adapter_path})
    return items


def tool_doctor(*, tag: str | None = None) -> dict:
    items = list_tools(tag=tag)
    return {
        "catalogued": len(items),
        "detected_on_path": sum(x["installed"] for x in items),
        "static_adapters_available": sum(x["adapter_available"] for x in items),
        "note": "PATH discovery only. Availability, entitlement, licensing and end-to-end functionality are NOT verified.",
        "tools": items,
    }


def run_static_adapter(tool_id: str, target: str | Path, *, allow_external: bool = False, timeout: float = 12) -> dict:
    if not allow_external:
        raise PermissionError("External tools are disabled; opt in with --allow-external")
    if tool_id not in STATIC_ADAPTERS:
        raise RegistryError(f"No vetted static adapter for {tool_id!r}; discovery-only tools cannot be executed")
    raw = Path(target).expanduser()
    if raw.is_symlink():
        raise RegistryError("Symlink target refused")
    resolved = raw.resolve(strict=True)
    if not resolved.is_file():
        raise RegistryError("Static adapter requires a regular file")
    if timeout <= 0 or timeout > 60:
        raise RegistryError("Timeout must be within 0-60 seconds")
    parts = STATIC_ADAPTERS[tool_id]
    executable = shutil.which(parts[0])
    if not executable:
        raise FileNotFoundError(f"Tool executable not found: {parts[0]}")
    command = [executable, *(str(resolved) if x == "{target}" else x for x in parts[1:])]
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        kwargs = {"stdout": stdout, "stderr": stderr, "stdin": subprocess.DEVNULL, "shell": False}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        process = subprocess.Popen(command, **kwargs)
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait()
            raise TimeoutError(f"Tool {tool_id} timed out after {timeout}s") from e
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read(131073)
        err = stderr.read(32769)
    return {
        "tool_id": tool_id,
        "target": str(resolved),
        "command": [Path(command[0]).name, *command[1:]],
        "exit_code": returncode,
        "elapsed_ms": round(1000 * (time.monotonic() - started)),
        "stdout": out[:131072].decode("utf-8", errors="replace"),
        "stderr": err[:32768].decode("utf-8", errors="replace"),
        "stdout_truncated": len(out) > 131072,
        "stderr_truncated": len(err) > 32768,
        "stdout_sha256_prefix": hashlib.sha256(out[:131072]).hexdigest(),
        "note": "External parser executed on the host. Inspect output; command success is not behavior verification.",
    }
