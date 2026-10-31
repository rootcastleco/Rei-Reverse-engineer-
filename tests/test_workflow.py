import tempfile
from pathlib import Path
import unittest

from rei_rea.workflow import investigate
from rei_rea.mcp import invoke_tool


class WorkflowTests(unittest.TestCase):
    def test_one_call_returns_consistent_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'demo.wasm'
            p.write_bytes(b'\0asm\x01\0\0\0')
            result = investigate(p)
            self.assertTrue(result['integrity']['stable_across_steps'])
            self.assertFalse(result['coverage']['target_executed'])
            self.assertEqual(result['structural']['status'], 'complete')
            self.assertEqual(result['signals']['sha256'], result['artifact']['sha256'])
            mcp_result = invoke_tool('rei_rea_investigate', {'target': str(p)})
            self.assertEqual(mcp_result['integrity']['sha256'], result['integrity']['sha256'])

    def test_oversized_pipeline_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'oversized'
            with p.open('wb') as f:
                f.truncate(64 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                investigate(p)

if __name__ == '__main__': unittest.main()
