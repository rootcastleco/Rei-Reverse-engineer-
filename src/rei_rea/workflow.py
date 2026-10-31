"""One-call, reproducible static investigation with cross-step identity checks."""
from __future__ import annotations

from pathlib import Path

from .deep import deep_inspect
from .inspector import inspect_path
from .planner import build_plan
from .signals import scan_signals

MAX_WORKFLOW_BYTES = 64 * 1024 * 1024


def investigate(target: str | Path) -> dict:
    first = inspect_path(target)
    if first["kind"] == "directory":
        raise ValueError("Single-shot investigation requires a regular file")
    if first["bytes"] > MAX_WORKFLOW_BYTES:
        raise ValueError("Single-shot investigation limit is 64 MiB; use individual bounded commands")
    deep = deep_inspect(first["path"])
    signals = scan_signals(first["path"], include_strings=False)
    final = inspect_path(first["path"])
    all_hashes = (first["sha256"], deep["artifact"]["sha256"] if deep.get("artifact") else None,
                  signals["sha256"], final["sha256"])
    if len(set(all_hashes)) != 1:
        raise ValueError("Target changed during analysis; discard findings and restart from stable bytes")
    return {"artifact": first, "structural": deep, "signals": signals,
            "plan": build_plan(first), "integrity": {"stable_across_steps": True, "sha256": first["sha256"]},
            "coverage": {"structure": deep["status"], "max_workflow_bytes": MAX_WORKFLOW_BYTES,
                         "target_executed": False, "external_tools_executed": False,
                         "secrets_in_strings_suppressed": True},
            "limitations": "Static inspection does not establish runtime behavior, vulnerability, provenance authenticity or parity."}
