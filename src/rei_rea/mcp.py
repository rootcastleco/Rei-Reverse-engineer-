"""Minimal dependency-free MCP stdio control plane (read-only tool surface)."""
from __future__ import annotations

import json
import sys

from . import __version__
from .evidence import create_case, verify_case
from .inspector import inspect_path
from .planner import build_plan
from .registry import list_tools, tool_doctor
from .signals import scan_signals, compare_files

PROTOCOL = "2025-03-26"
MAX_INBOUND = 1024 * 1024


def _tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {"name": f"rei_rea_{name}", "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}}


TOOLS = [
    _tool("tools", "List centrally catalogued RE tools; installed means executable on PATH, NOT integrated or licensed.",
          {"tag": {"type": "string"}, "installed_only": {"type": "boolean"}}),
    _tool("doctor", "Read-only PATH capability audit. Never launches external tools.", {"tag": {"type": "string"}}),
    _tool("inspect", "Read-only SHA-256, bounded magic and archive inventory. Does not execute target.",
          {"target": {"type": "string"}}, ["target"]),
    _tool("plan", "Produce artifact-specific investigation steps, skills and tool candidates.",
          {"target": {"type": "string"}}, ["target"]),
    _tool("signals", "Analyze bounded entropy and embedded signatures; raw strings opt-in and may be sensitive.",
          {"target": {"type": "string"}, "include_strings": {"type": "boolean"}}, ["target"]),
    _tool("compare", "Read-only SHA-256 and bounded byte comparison of two authorized local artifacts.",
          {"before": {"type": "string"}, "after": {"type": "string"}}, ["before", "after"]),
    _tool("case_create", "Create a local evidence case and hash-chain entry; metadata only; no artifact copy.",
          {"target": {"type": "string"}, "workspace": {"type": "string"}}, ["target"]),
    _tool("case_verify", "Verify the local evidence hash chain; optional target recheck.",
          {"case_path": {"type": "string"}, "recheck_target": {"type": "boolean"}}, ["case_path"]),
]


def invoke_tool(name: str, a: dict) -> dict:
    if not isinstance(a, dict):
        raise ValueError("Tool arguments must be an object")
    tool = next((t for t in TOOLS if t["name"] == name), None)
    if tool is None:
        raise ValueError("Unknown REI REA tool")
    schema = tool["inputSchema"]
    if set(a) - set(schema["properties"]):
        raise ValueError("Unrecognized argument")
    if set(schema["required"]) - set(a):
        raise ValueError("Required tool argument missing")
    for key, value in a.items():
        if not isinstance(value, bool if schema["properties"][key]["type"] == "boolean" else str):
            raise ValueError(f"Wrong value type for argument: {key}")
    if name == "rei_rea_tools":
        return {"tools": list_tools(tag=a.get("tag"), installed_only=a.get("installed_only", False))}
    if name == "rei_rea_doctor":
        return tool_doctor(tag=a.get("tag"))
    if name == "rei_rea_inspect":
        return inspect_path(a["target"])
    if name == "rei_rea_plan":
        inspection = inspect_path(a["target"])
        return {"inspection": inspection, "plan": build_plan(inspection)}
    if name == "rei_rea_signals":
        return scan_signals(a["target"], include_strings=a.get("include_strings", False))
    if name == "rei_rea_compare":
        return compare_files(a["before"], a["after"])
    if name == "rei_rea_case_create":
        return create_case(a["target"], a.get("workspace", ".rei-cases"))
    if name == "rei_rea_case_verify":
        return verify_case(a["case_path"], recheck_target=a.get("recheck_target", False))
    raise ValueError("Unknown tool")


def _result(request: dict) -> dict | None:
    ident = request.get("id")
    method = request.get("method")
    if method == "notifications/initialized" or ("id" not in request and method):
        return None
    try:
        if method == "initialize":
            value = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                     "serverInfo": {"name": "rootcastle-rei-rea", "version": __version__}}
        elif method == "ping":
            value = {}
        elif method == "tools/list":
            value = {"tools": TOOLS}
        elif method == "tools/call":
            params = request.get("params") or {}
            response = invoke_tool(params.get("name", ""), params.get("arguments") or {})
            value = {"content": [{"type": "text", "text": json.dumps(response, ensure_ascii=False)}], "isError": False}
        elif method == "resources/list":
            value = {"resources": []}
        elif method == "prompts/list":
            value = {"prompts": []}
        else:
            return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": ident, "result": value}
    except (OSError, ValueError, KeyError, PermissionError, TimeoutError) as exc:
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": ident, "result": {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True}}
        return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32602, "message": str(exc)}}


def serve_stdio() -> None:
    inb = sys.stdin.buffer
    out = sys.stdout.buffer
    while True:
        line = inb.readline(MAX_INBOUND + 1)
        if not line:
            return
        if len(line) > MAX_INBOUND:
            out.write(b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Message too large"}}\n')
            out.flush()
            # A valid MCP client would never send oversized messages; close transport safely.
            return
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("Expected JSON-RPC 2.0 object")
            reply = _result(request)
        except (ValueError, TypeError) as exc:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        if reply is not None:
            out.write(json.dumps(reply, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
            out.flush()


if __name__ == "__main__":
    serve_stdio()
