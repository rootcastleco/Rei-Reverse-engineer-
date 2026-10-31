import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from rei_rea.casebook import index_cases, search_cases, bundle_case, verify_bundle
from rei_rea.evidence import create_case, append_event


class CasebookTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.workspace = self.root / 'cases'
        self.p = self.root / 'sample'
        self.p.write_bytes(b'\0asm\x01\0\0\0')
        self.case = Path(create_case(self.p, self.workspace)['case_path'])

    def test_index_and_search_case_metadata(self):
        indexed = index_cases(self.workspace)
        self.assertEqual(indexed['indexed'], 1)
        self.assertEqual(indexed['valid'], 1)
        results = search_cases(self.workspace, kind='wasm')
        self.assertEqual(results['total_matches'], 1)
        self.assertNotIn('payload', json.dumps(results))
        self.assertEqual(search_cases(self.workspace, query="%' OR 1=1--")['total_matches'], 0)
        self.assertEqual(search_cases(self.workspace, query='not-present')['total_matches'], 0)
        self.assertEqual(search_cases(self.workspace, kind='pe')['total_matches'], 0)
        with self.assertRaises(ValueError):
            search_cases(self.workspace, limit=101)

    def test_reindex_recognizes_case_tamper(self):
        index_cases(self.workspace)
        row = json.loads((self.case / 'events.jsonl').read_text().splitlines()[0])
        row['payload']['kind'] = 'altered'
        (self.case / 'events.jsonl').write_text(json.dumps(row) + '\n')
        updated = index_cases(self.workspace)
        self.assertEqual(updated['invalid'], 1)
        self.assertEqual(search_cases(self.workspace)['results'][0]['chain_valid'], 0)

    def test_bundle_export_verify_tamper(self):
        append_event(self.case, 'analyst-note', {'text': 'evidence'}, confidence='inferred')
        out = self.root / 'case.zip'
        exported = bundle_case(self.case, out)
        self.assertFalse(exported['target_bytes_included'])
        self.assertTrue(verify_bundle(out)['valid'])
        with zipfile.ZipFile(out) as z:
            self.assertEqual(len(z.namelist()), 4)
            original = {x: z.read(x) for x in z.namelist()}
        with zipfile.ZipFile(out, 'w') as z:
            for name, data in original.items():
                z.writestr(name, data + b'changed' if name == 'report.md' else data)
        self.assertFalse(verify_bundle(out)['valid'])
        with self.assertRaises(FileExistsError):
            bundle_case(self.case, out)

    def test_search_requires_explicit_index(self):
        with self.assertRaises(FileNotFoundError):
            search_cases(self.workspace)


if __name__ == '__main__': unittest.main()
