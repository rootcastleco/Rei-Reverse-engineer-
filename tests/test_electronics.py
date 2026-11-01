import tempfile
import unittest
from pathlib import Path
from rei_rea.electronics import FORMAT_REGISTRY, _intel_hex, _srec, _uf2, inspect_electronics
from rei_rea.mcp import invoke_tool

class ElectronicsTests(unittest.TestCase):
    def test_registry(self):
        self.assertGreaterEqual(len(FORMAT_REGISTRY), 70)
    def test_hex(self):
        self.assertTrue(_intel_hex(b":00000001FF\n"))
        self.assertFalse(_intel_hex(b":0000000100\n"))
    def test_srecord(self):
        self.assertTrue(_srec(b"S9030000FC\n"))
        self.assertFalse(_srec(b"S903000000\n"))
    def test_uf2(self):
        self.assertFalse(_uf2(b"UF2\n"))
    def test_kicad(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"board.kicad_pcb"
            p.write_text("(kicad_pcb (version 20240108))", encoding="utf-8")
            self.assertEqual(inspect_electronics(p)["signature_evidence"], "kicad-text-header")
            self.assertEqual(invoke_tool("rei_rea_electronics", {"target":str(p)})["claimed_family"],"pcb-cad")
    def test_extension_not_proof(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fake.gbr"
            p.write_bytes(b"junk")
            self.assertIsNone(inspect_electronics(p)["signature_evidence"])
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"a.hex";p.write_bytes(b"x")
            alias=Path(d)/"b.hex"
            try: alias.symlink_to(p)
            except OSError: self.skipTest("No symlink privilege")
            with self.assertRaises(ValueError): inspect_electronics(alias)
