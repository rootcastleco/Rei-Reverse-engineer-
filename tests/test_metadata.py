"""Offline test coverage for discoverability metadata and GitHub API orchestration."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.sync_github_metadata import DEFAULT_METADATA, load_metadata, sync


class MetadataTests(unittest.TestCase):
    def test_metadata_has_valid_repository_description_and_topics(self):
        doc = load_metadata(DEFAULT_METADATA)
        self.assertEqual(doc['repository'], 'rootcastleco/Rei-Reverse-engineer')
        self.assertGreaterEqual(len(doc['topics']), 10)
        self.assertIn('reverse-engineering', doc['topics'])
        self.assertIn('mcp-server', doc['topics'])

    def test_duplicate_topic_rejected(self):
        base = load_metadata(DEFAULT_METADATA)
        base['topics'].append(base['topics'][0])
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / 'meta.json'
            f.write_text(json.dumps(base), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                load_metadata(f)

    def test_more_than_twenty_topics_rejected(self):
        base = load_metadata(DEFAULT_METADATA)
        base['topics'] = ['topic-' + str(i) for i in range(21)]
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / 'meta.json'
            f.write_text(json.dumps(base), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '1 to 20'):
                load_metadata(f)

    @patch('scripts.sync_github_metadata.github_api')
    def test_sync_patches_repo_and_replaces_topics_then_verifies(self, api):
        desired = load_metadata(DEFAULT_METADATA)
        api.side_effect = [{}, {}, {
            'description': desired['description'],
            'homepage': desired['homepage'],
            'topics': desired['topics'],
        }]
        result = sync(desired, 'test-token')
        self.assertTrue(result['verified'])
        self.assertEqual([c.args[0] for c in api.call_args_list], ['PATCH', 'PUT', 'GET'])
        self.assertEqual(api.call_args_list[1].args[3]['names'], desired['topics'])

    @patch('scripts.sync_github_metadata.github_api')
    def test_sync_reports_verification_mismatch(self, api):
        desired = load_metadata(DEFAULT_METADATA)
        api.side_effect = [{}, {}, {'description': 'old', 'homepage': '', 'topics': []}]
        with self.assertRaisesRegex(RuntimeError, 'expected metadata'):
            sync(desired, 'test-token')


if __name__ == '__main__':
    unittest.main()
