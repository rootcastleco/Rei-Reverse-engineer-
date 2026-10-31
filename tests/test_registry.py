import tempfile
from pathlib import Path
import unittest
from rei_rea.registry import load_catalog, list_tools, run_static_adapter, tool_doctor, RegistryError


class RegistryTests(unittest.TestCase):
    def test_catalog_consistency(self):
        items = load_catalog()
        self.assertGreaterEqual(len(items), 120)
        self.assertEqual(len(items), len({t["id"] for t in items}))
        self.assertIn("frida", {t["id"] for t in items})
        self.assertIn("ghidra", {t["id"] for t in items})
        self.assertTrue(all(t["bundled"] is False for t in items))

    def test_doctor_and_filters(self):
        info = tool_doctor(tag="android")
        self.assertGreater(info["catalogued"], 10)
        self.assertLessEqual(info["detected_on_path"], info["catalogued"])
        found = list_tools(tag="native", installed_only=True)
        self.assertTrue(all(t["installed"] for t in found))

    def test_external_requires_opt_in_and_fixed_adapter(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "foo"
            target.write_bytes(b"ELF")
            with self.assertRaises(PermissionError):
                run_static_adapter("file", target)
            with self.assertRaises(RegistryError):
                run_static_adapter("frida", target, allow_external=True)
            with self.assertRaises(RegistryError):
                run_static_adapter("file", target, allow_external=True, timeout=1000)

    def test_static_file_adapter_if_available(self):
        import shutil
        if not shutil.which("file"):
            self.skipTest("file command absent")
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "hello.bin"
            target.write_bytes(b"text 123\n")
            result = run_static_adapter("file", target, allow_external=True)
            self.assertEqual(result["exit_code"], 0)
            self.assertIn("text", result["stdout"].lower())


if __name__ == "__main__":
    unittest.main()
