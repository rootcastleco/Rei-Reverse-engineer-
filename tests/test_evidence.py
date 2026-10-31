import json
from pathlib import Path
import tempfile
import unittest

from rei_rea.evidence import append_event, create_case, render_report, verify_case


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "artifact.bin"
        self.target.write_bytes(b"test\x00artifact")
        self.case = Path(create_case(self.target, self.root / "cases")["case_path"])

    def test_create_append_verify_report(self):
        self.assertTrue(verify_case(self.case)["valid"])
        append_event(self.case, "analyst-note", {"offset": "0x0", "fact": "test"}, confidence="inferred")
        result = verify_case(self.case, recheck_target=True)
        self.assertTrue(result["valid"])
        self.assertEqual(result["event_count"], 2)
        report = render_report(self.case)
        self.assertIn("SHA-256", report)
        self.assertIn("No code behavior", report)

    def test_tampered_event_detected(self):
        p = self.case / "events.jsonl"
        row = json.loads(p.read_text().splitlines()[0])
        row["payload"]["kind"] = "modified"
        p.write_text(json.dumps(row) + "\n")
        result = verify_case(self.case)
        self.assertFalse(result["valid"])
        with self.assertRaises(ValueError):
            append_event(self.case, "analyst-note", {"foo": 1})

    def test_recheck_detects_target_mutation(self):
        self.target.write_bytes(b"different")
        self.assertTrue(verify_case(self.case)["valid"])
        self.assertFalse(verify_case(self.case, recheck_target=True)["valid"])

    def test_duplicate_case_creates_new_folder(self):
        case2 = create_case(self.target, self.root / "cases")
        self.assertNotEqual(str(self.case), case2["case_path"])


if __name__ == "__main__":
    unittest.main()
