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


class V02CliTests(unittest.TestCase):
    def test_structural_and_pipeline_cli(self):
        from rei_rea.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'sample.wasm'
            p.write_bytes(b'\0asm\x01\0\0\0')
            self.assertEqual(main(['deep', str(p)]), 0)
            self.assertEqual(main(['investigate', str(p)]), 0)
            self.assertEqual(main(['diff', str(p), str(p)]), 0)

    def test_casebook_commands(self):
        from rei_rea.cli import main
        from rei_rea.evidence import create_case
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'file'; target.write_bytes(b'abcd')
            case = create_case(target, root / 'cases')['case_path']
            self.assertEqual(main(['case','index',str(root / 'cases')]), 0)
            self.assertEqual(main(['case','search',str(root / 'cases'),'--query','file']), 0)
            archive = root / 'bundle.zip'
            self.assertEqual(main(['case','bundle',case,str(archive)]), 0)
            self.assertEqual(main(['case','bundle-verify',str(archive)]), 0)
