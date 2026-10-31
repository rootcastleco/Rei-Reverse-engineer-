import tempfile
import unittest
from pathlib import Path
import struct
import zipfile

from rei_rea.inspector import inspect_path, sha256_file


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_elf_identify_and_hash(self):
        p = self.root / "sample.bin"
        p.write_bytes(b"\x7fELF" + bytes([2, 1]) + bytes(12) + (62).to_bytes(2, "little") + bytes(80))
        result = inspect_path(p)
        self.assertEqual(result["kind"], "elf")
        self.assertEqual(result["observations"]["bits"], 64)
        self.assertEqual(result["observations"]["machine"], 62)
        self.assertEqual(result["sha256"], sha256_file(p))

    def test_pe_header(self):
        blob = bytearray(200)
        blob[0:2] = b"MZ"
        struct.pack_into("<I", blob, 0x3C, 96)
        blob[96:100] = b"PE\0\0"
        struct.pack_into("<H", blob, 100, 0x8664)
        struct.pack_into("<H", blob, 102, 3)
        p = self.root / "sample.exe"
        p.write_bytes(blob)
        result = inspect_path(p)
        self.assertEqual(result["kind"], "pe")
        self.assertEqual(result["observations"]["sections_declared"], 3)

    def test_apk_detected_by_members_not_suffix(self):
        p = self.root / "not_an_apk.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("AndroidManifest.xml", b"fake")
            z.writestr("classes.dex", b"dex\n035\x00")
            z.writestr("res/x", b"data")
        result = inspect_path(p)
        self.assertEqual(result["kind"], "apk")
        self.assertEqual(result["observations"]["archive_entries"], 3)

    def test_archive_path_traversal_raises_warning_without_extracting(self):
        p = self.root / "unsafe.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("../escape.txt", b"payload")
        result = inspect_path(p)
        self.assertTrue(result["observations"]["unsafe_entry_paths_sample"])
        self.assertFalse((self.root.parent / "escape.txt").exists())

    def test_java_and_mach_fat_disambiguation(self):
        java = self.root / "App.class"
        java.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + bytes(30))
        self.assertEqual(inspect_path(java)["kind"], "java-class")
        fat = self.root / "fat"
        fat.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(30))
        self.assertEqual(inspect_path(fat)["kind"], "mach-o-fat")

    def test_symlink_refused(self):
        p = self.root / "x"
        p.write_text("payload")
        link = self.root / "link"
        try:
            link.symlink_to(p)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks not supported")
        with self.assertRaises(ValueError):
            inspect_path(link)

    def test_directory_content_identity_changes(self):
        p = self.root / "source"
        p.mkdir()
        (p / "x.js").write_text("hello")
        first = inspect_path(p)
        self.assertEqual(first["kind"], "directory")
        (p / "x.js").write_text("world")
        second = inspect_path(p)
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_missing_path_fails(self):
        with self.assertRaises(FileNotFoundError):
            inspect_path(self.root / "missing")


if __name__ == "__main__":
    unittest.main()
