import os
from pathlib import Path
import random
import struct
import tempfile
import unittest

from rei_rea.deep import deep_inspect, structural_diff, pe_profile, elf_profile, wasm_profile, ParseError


def make_pe(api=b'CreateFileW'):
    d = bytearray(0x1200)
    d[:2] = b'MZ'
    struct.pack_into('<I', d, 0x3c, 0x80)
    d[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', d, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x102)
    opt = 0x98
    struct.pack_into('<H', d, opt, 0x10b)
    struct.pack_into('<I', d, opt + 16, 0x1234)
    struct.pack_into('<I', d, opt + 28, 0x400000)
    struct.pack_into('<I', d, opt + 60, 0x400)
    struct.pack_into('<H', d, opt + 70, 0x140)
    struct.pack_into('<I', d, opt + 92, 16)
    struct.pack_into('<II', d, opt + 104, 0x1100, 0x80)
    d[opt + 224:opt + 232] = b'.rdata\0\0'
    struct.pack_into('<IIII', d, opt + 232, 0x1000, 0x1000, 0x1000, 0x400)
    struct.pack_into('<I', d, opt + 260, 0x40000040)
    struct.pack_into('<IIIII', d, 0x500, 0x1200, 0, 0, 0x1300, 0x1210)
    struct.pack_into('<I', d, 0x600, 0x1400)
    d[0x700:0x70d] = b'KERNEL32.dll\0'
    d[0x800:0x802] = b'\x00\x00'
    d[0x802:0x802 + len(api) + 1] = api + b'\0'
    return bytes(d)


def make_elf():
    d = bytearray(0x400)
    d[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', d, 16, 3, 62, 1, 0x400120, 0x40, 0x200, 0, 64, 56, 1, 64, 3, 0)
    struct.pack_into('<IIQQQQQQ', d, 0x40, 0x6474e551, 6, 0, 0, 0, 0, 0, 0)
    d[0x100:0x10b] = b'\0libc.so.6\0'
    struct.pack_into('<qQ', d, 0x140, 1, 1)
    struct.pack_into('<qQ', d, 0x150, 0, 0)
    struct.pack_into('<IIQQQQIIQQ', d, 0x240, 0, 3, 0, 0, 0x100, 11, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', d, 0x280, 0, 6, 0, 0, 0x140, 32, 1, 0, 8, 16)
    return bytes(d)


def leb(value):
    out = bytearray()
    while True:
        bit = value & 127
        value >>= 7
        out.append(bit | 128 if value else bit)
        if not value:
            return bytes(out)


def named(value):
    return leb(len(value)) + value


def make_wasm(export=b'run'):
    imp = leb(1) + named(b'env') + named(b'api') + b'\0' + leb(0)
    exp = leb(1) + named(export) + b'\0' + leb(0)
    return b'\0asm\x01\0\0\0' + b'\x02' + leb(len(imp)) + imp + b'\x07' + leb(len(exp)) + exp


class DeepTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def target(self, name, content):
        p = self.root / name
        p.write_bytes(content)
        return p

    def test_pe_sections_imports_and_flags(self):
        p = self.target('a.exe', make_pe())
        result = deep_inspect(p)
        self.assertEqual(result['status'], 'complete')
        pe = result['profile']
        self.assertEqual(pe['pe_bits'], 32)
        self.assertEqual(pe['sections'][0]['name'], '.rdata')
        self.assertEqual(pe['imports'][0]['library'], 'KERNEL32.dll')
        self.assertEqual(pe['imports'][0]['functions'][0]['name'], 'CreateFileW')
        self.assertTrue(pe['nx_compat_flag'])
        self.assertTrue(pe['aslr_dynamic_base_flag'])

    def test_elf_dynamic_dependencies(self):
        result = deep_inspect(self.target('a.elf', make_elf()))
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['profile']['needed_libraries'], ['libc.so.6'])
        self.assertFalse(result['profile']['gnu_stack_executable_flag'])

    def test_wasm_import_export_and_diff(self):
        a = self.target('a.wasm', make_wasm())
        b = self.target('b.wasm', make_wasm(b'next'))
        result = deep_inspect(a)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['profile']['imports_sample'][0]['module'], 'env')
        self.assertEqual(result['profile']['exports_sample'][0]['name'], 'run')
        diff = structural_diff(a, b)
        self.assertIn('exports_sample', diff['structural_changes'])
        self.assertFalse(diff['partial'])

    def test_malformed_and_bounded(self):
        pe = make_pe()[:150]
        result = deep_inspect(self.target('broken.exe', pe))
        self.assertIn(result['status'], {'invalid', 'unsupported'})
        bad = self.target('bad.wasm', b'\0asm\x01\0\0\0\x07\x80')
        self.assertEqual(deep_inspect(bad)['status'], 'invalid')
        self.assertEqual(deep_inspect(self.target('unknown.bin', b'xx'))['status'], 'unsupported')
        for fn, prefix in ((pe_profile, b'MZ'), (elf_profile, b'\x7fELF'), (wasm_profile, b'\0asm')):
            for seed in range(100):
                data = prefix + random.Random(seed).randbytes(seed % 80)
                try:
                    fn(data)
                except (ParseError, struct.error):
                    pass

    def test_refuses_target_symlink(self):
        p = self.target('real.wasm', make_wasm())
        link = self.root / 'link.wasm'
        try:
            link.symlink_to(p)
        except (OSError, NotImplementedError):
            self.skipTest('No symlinks')
        with self.assertRaises(ValueError):
            deep_inspect(link)


if __name__ == '__main__': unittest.main()
