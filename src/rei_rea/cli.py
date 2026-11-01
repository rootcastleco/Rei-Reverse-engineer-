"""Cross-platform CLI: all default actions are read-only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import sqlite3
import zipfile

from . import __version__
from .evidence import append_event, create_case, render_report, verify_case
from .inspector import inspect_path
from .planner import build_plan
from .registry import list_tools, run_static_adapter, tool_doctor
from .signals import scan_signals, compare_files
from .deep import deep_inspect, structural_diff
from .casebook import index_cases, search_cases, bundle_case, verify_bundle
from .workflow import investigate
from .providers import list_providers, inspect_provider
from .electronics import inspect_electronics


def _json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rei-rea", description="Rootcastle REI REA: evidence-first reverse-engineering workbench")
    p.add_argument("--version", action="version", version=f"REI REA {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    tools = sub.add_parser("tools", help="Central catalog and PATH availability")
    ts = tools.add_subparsers(dest="tools_command", required=True)
    for cmd in ("list", "doctor"):
        leaf = ts.add_parser(cmd)
        leaf.add_argument("--tag", help="Filter by capability tag or category")
        if cmd == "list":
            leaf.add_argument("--installed-only", action="store_true")
    providers = sub.add_parser("providers", help="List or inspect via reviewed provider adapters")
    ps = providers.add_subparsers(dest="provider_command", required=True)
    ps.add_parser("list", help="Discover 12 providers without executing tools")
    pi = ps.add_parser("inspect", help="Explicitly run one approved static provider")
    pi.add_argument("provider_id")
    pi.add_argument("target")
    pi.add_argument("--allow-external", action="store_true")
    pi.add_argument("--timeout", type=float, default=12)
    ep = sub.add_parser("electronics", help="Bounded electronics/PCB/firmware file intake")
    ep.add_argument("target")
    insp = sub.add_parser("inspect", help="Hash and identify an artifact without executing it")
    insp.add_argument("target")
    plan = sub.add_parser("plan", help="Generate a source/evidence-first investigation plan")
    plan.add_argument("target")
    signals = sub.add_parser("signals", help="Bounded entropy and embedded-signature analysis")
    signals.add_argument("target")
    signals.add_argument("--include-strings", action="store_true", help="Show raw ASCII strings; review for sensitive data")
    inv = sub.add_parser("investigate", help="Run bounded all-in-one static evidence pipeline")
    inv.add_argument("target")
    deep = sub.add_parser("deep", help="Parse bounded PE/ELF/WASM sections, imports and symbols without running target")
    deep.add_argument("target")
    structural = sub.add_parser("diff", help="Compare static PE/ELF/WASM structures across revisions")
    structural.add_argument("before")
    structural.add_argument("after")
    compare = sub.add_parser("compare", help="Compare two local files, hashes and byte offsets")
    compare.add_argument("before")
    compare.add_argument("after")
    case = sub.add_parser("case", help="Local chain-of-evidence case operations")
    cs = case.add_subparsers(dest="case_command", required=True)
    ci = cs.add_parser("init", help="Create immutable target identity and chain")
    ci.add_argument("target")
    ci.add_argument("--workspace", default=".rei-cases")
    cv = cs.add_parser("verify", help="Verify chain and optionally re-hash target")
    cv.add_argument("case_path")
    cv.add_argument("--recheck-target", action="store_true")
    cn = cs.add_parser("note", help="Append a source-attributed analyst observation")
    cn.add_argument("case_path")
    cn.add_argument("--type", default="analyst-note")
    cn.add_argument("--text", required=True)
    cn.add_argument("--source", default="analyst-supplied")
    cn.add_argument("--confidence", choices=("observed", "inferred", "unknown"), default="inferred")
    cr = cs.add_parser("report", help="Render current case provenance report")
    cr.add_argument("case_path")
    cr.add_argument("--output", help="Write Markdown to this explicit path")
    cx = cs.add_parser("index", help="Explicitly refresh a local, metadata-only SQLite casebook")
    cx.add_argument("workspace")
    csearch = cs.add_parser("search", help="Search an existing casebook without modifying it")
    csearch.add_argument("workspace")
    csearch.add_argument("--query", default="")
    csearch.add_argument("--kind", default="")
    csearch.add_argument("--limit", type=int, default=25)
    cb = cs.add_parser("bundle", help="Export verified case metadata only, never the artifact")
    cb.add_argument("case_path")
    cb.add_argument("output")
    bv = cs.add_parser("bundle-verify", help="Verify metadata bundle checksums (not authenticity)")
    bv.add_argument("bundle_path")
    run = sub.add_parser("run", help="Run one fixed, vetted static adapter (explicit opt-in)")
    run.add_argument("tool_id")
    run.add_argument("target")
    run.add_argument("--allow-external", action="store_true", help="Confirm an external parser may inspect this local file")
    run.add_argument("--timeout", type=float, default=12)
    run.add_argument("--case", dest="case_path")
    sub.add_parser("mcp", help="Start one stdio MCP endpoint for discovery and static evidence")
    serve = sub.add_parser("serve", help="Serve local-only read-only catalog dashboard")
    serve.add_argument("--port", type=int, default=8765)
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        if a.command == "tools":
            if a.tools_command == "list":
                _json({"tools": list_tools(tag=a.tag, installed_only=a.installed_only)})
            else:
                _json(tool_doctor(tag=a.tag))
        elif a.command == "providers":
            if a.provider_command == "list":
                _json(list_providers())
            else:
                result = inspect_provider(a.provider_id, a.target, allow_external=a.allow_external, timeout=a.timeout)
                _json(result)
                return 0 if result["result"]["exit_code"] == 0 else 4
        elif a.command == "electronics":
            _json(inspect_electronics(a.target))
        elif a.command == "inspect":
            _json(inspect_path(a.target))
        elif a.command == "plan":
            result = inspect_path(a.target)
            _json({"inspection": result, "plan": build_plan(result)})
        elif a.command == "signals":
            _json(scan_signals(a.target, include_strings=a.include_strings))
        elif a.command == "investigate":
            _json(investigate(a.target))
        elif a.command == "deep":
            _json(deep_inspect(a.target))
        elif a.command == "diff":
            _json(structural_diff(a.before, a.after))
        elif a.command == "compare":
            _json(compare_files(a.before, a.after))
        elif a.command == "case":
            if a.case_command == "init":
                _json(create_case(a.target, a.workspace))
            elif a.case_command == "verify":
                result = verify_case(a.case_path, recheck_target=a.recheck_target)
                _json(result)
                return 0 if result["valid"] else 3
            elif a.case_command == "index":
                _json(index_cases(a.workspace))
            elif a.case_command == "search":
                _json(search_cases(a.workspace, query=a.query, kind=a.kind, limit=a.limit))
            elif a.case_command == "bundle":
                _json(bundle_case(a.case_path, a.output))
            elif a.case_command == "bundle-verify":
                result = verify_bundle(a.bundle_path)
                _json(result)
                return 0 if result["valid"] else 3
            elif a.case_command == "note":
                _json(append_event(a.case_path, a.type, {"text": a.text, "source": a.source}, confidence=a.confidence))
            else:
                report = render_report(a.case_path)
                if a.output:
                    Path(a.output).write_text(report, encoding="utf-8")
                    _json({"report_path": str(Path(a.output).resolve())})
                else:
                    print(report, end="")
        elif a.command == "run":
            if a.case_path:
                case_path = Path(a.case_path)
                manifest = json.loads((case_path / "case.json").read_text(encoding="utf-8"))
                current = inspect_path(a.target)
                if (current["sha256"] != manifest["target"]["sha256"]
                        or current["identity_complete"] != manifest["target"]["identity_complete"]):
                    raise ValueError("Tool target identity differs from selected case")
            result = run_static_adapter(a.tool_id, a.target, allow_external=a.allow_external, timeout=a.timeout)
            if a.case_path:
                append_event(case_path, "static-tool-result", {"tool_id": a.tool_id, "exit_code": result["exit_code"],
                            "stdout_sha256_prefix": result["stdout_sha256_prefix"], "elapsed_ms": result["elapsed_ms"]})
            _json(result)
            return 0 if result["exit_code"] == 0 else 4
        elif a.command == "mcp":
            from .mcp import serve_stdio
            serve_stdio()
        elif a.command == "serve":
            from .web import serve_local
            serve_local(a.port)
        return 0
    except (OSError, ValueError, PermissionError, TimeoutError, KeyError, sqlite3.DatabaseError, zipfile.BadZipFile) as e:
        print(f"rei-rea: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
