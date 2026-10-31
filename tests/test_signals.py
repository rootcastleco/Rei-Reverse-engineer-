import tempfile
import unittest
from pathlib import Path
from rei_rea.signals import scan_signals, compare_files

class SignalsTests(unittest.TestCase):
    def test_signals_bounded_and_string_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'sample.bin'
            target.write_bytes(b'ZZ'+b'\x7fELF'+b'\x00'*300+b'DIAGNOSTIC-STRING-123')
            safe=scan_signals(target)
            self.assertNotIn('ascii_strings_sample', safe)
            self.assertEqual(safe['embedded_signatures'][0]['offset'],2)
            exposed=scan_signals(target,include_strings=True)
            self.assertIn('DIAGNOSTIC-STRING-123',str(exposed['ascii_strings_sample']))

    def test_byte_compare(self):
        with tempfile.TemporaryDirectory() as tmp:
            x,y=Path(tmp)/'x',Path(tmp)/'y'
            x.write_bytes(b'abc')
            y.write_bytes(b'aBc!')
            cmp=compare_files(x,y)
            self.assertFalse(cmp['identical_sha256'])
            self.assertEqual(cmp['different_bytes_in_scanned_overlap'],1)
            self.assertEqual(cmp['first_differing_offsets'][0]['offset'],1)
            self.assertEqual(cmp['byte_length_delta'],1)

if __name__=='__main__': unittest.main()
