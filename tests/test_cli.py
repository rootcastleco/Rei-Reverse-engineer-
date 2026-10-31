import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from rei_rea.web import CatalogHandler


class CliTests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([sys.executable, "-m", "rei_rea", *args], capture_output=True,
                              text=True, timeout=10)

    def test_inspect_and_plan_cli(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "demo.wasm"
            target.write_bytes(b"\0asm\x01\0\0\0")
            result = self.call("inspect", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["kind"], "wasm")
            plan = self.call("plan", str(target))
            self.assertEqual(json.loads(plan.stdout)["plan"]["artifact_kind"], "wasm")

    def test_case_cli(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "sample.bin"
            target.write_bytes(b"x")
            result = self.call("case", "init", str(target), "--workspace", str(Path(d)/"cases"))
            self.assertEqual(result.returncode, 0, result.stderr)
            case_path = json.loads(result.stdout)["case_path"]
            result = self.call("case", "verify", case_path, "--recheck-target")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["valid"])

    def test_external_is_not_auto_executed(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "sample.bin"
            target.write_bytes(b"foo")
            result = self.call("run", "file", str(target))
            self.assertEqual(result.returncode, 2)
            self.assertIn("disabled", result.stderr)

    def test_http_handler_headers_defined(self):
        self.assertTrue(callable(CatalogHandler.do_GET))


if __name__ == "__main__":
    unittest.main()
