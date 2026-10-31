import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from rei_rea.mcp import TOOLS, _result, invoke_tool
from rei_rea.planner import build_plan
from rei_rea.inspector import inspect_path


class McpTests(unittest.TestCase):
    def test_schema_names_are_unique(self):
        self.assertEqual(len(TOOLS), len({x["name"] for x in TOOLS}))
        self.assertTrue(all(x["name"].startswith("rei_rea_") for x in TOOLS))

    def test_initialize_and_tools_list(self):
        res = _result({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        self.assertEqual(res["result"]["serverInfo"]["name"], "rootcastle-rei-rea")
        self.assertIn("tools", _result({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"])
        self.assertIsNone(_result({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_invalid_call_returns_tool_error(self):
        res = _result({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "rei_rea_inspect", "arguments": {"target": "missing.file"}}})
        self.assertTrue(res["result"]["isError"])
        with self.assertRaises(ValueError):
            invoke_tool("rei_rea_inspect", {"target": "foo", "unexpected": "bad"})

    def test_plan_static(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "firmware.bin"
            p.write_bytes(b"\x00asm\x01\x00\x00\x00")
            result = build_plan(inspect_path(p))
            self.assertEqual(result["artifact_kind"], "wasm")
            self.assertIn("rei-wasm-and-managed", result["skill_routes"])

    def test_stdio_json_rpc_handshake(self):
        body = "\n".join(json.dumps(x) for x in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]) + "\n"
        proc = subprocess.run([sys.executable, "-m", "rei_rea.mcp"], input=body, text=True,
                              capture_output=True, check=True, timeout=5)
        rows = [json.loads(x) for x in proc.stdout.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(rows[1]["result"]["tools"][0]["name"], "rei_rea_tools")
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
