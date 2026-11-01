import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rei_rea.discovery import resolve_executables, _windows_names
from rei_rea.registry import STATIC_ADAPTERS, load_catalog, tool_doctor


class DiscoveryTests(unittest.TestCase):
    def test_permission_denied_inventory_falls_back_to_resolver(self):
        with patch('rei_rea.discovery.os.scandir', side_effect=PermissionError):
            self.assertIsNone(_windows_names())
        with patch('rei_rea.discovery.sys.platform', 'win32'), patch('rei_rea.discovery._windows_names', return_value=None), patch('rei_rea.discovery.shutil.which', side_effect=lambda name: '/found/'+name):
            self.assertEqual(resolve_executables(['a', 'b', 'a']), {'a': '/found/a', 'b': '/found/b'})

    def test_catalog_and_adapters_agree_in_both_directions(self):
        catalog = load_catalog()
        self.assertEqual({t['id'] for t in catalog if t['integration'] == 'static-adapter'}, set(STATIC_ADAPTERS))
        for tool in catalog:
            if tool['id'] in STATIC_ADAPTERS:
                self.assertIn(STATIC_ADAPTERS[tool['id']][0], tool['executables'])

    def test_duplicate_probes_resolved_once(self):
        with patch('rei_rea.discovery.sys.platform', 'linux'), patch('rei_rea.discovery.shutil.which', return_value=None) as which:
            self.assertEqual(resolve_executables(['missing', 'missing']), {'missing': None})
            which.assert_called_once_with('missing')

    def test_windows_prefilter_preserves_final_resolver_authority(self):
        with patch('rei_rea.discovery.sys.platform', 'win32'), patch('rei_rea.discovery._windows_names', return_value={'tool'}), patch('rei_rea.discovery.shutil.which', return_value=None) as which:
            self.assertEqual(resolve_executables(['tool', 'absent']), {'tool': None, 'absent': None})
            which.assert_called_once_with('tool')

    def test_directory_inventory_is_fresh_case_insensitive_and_handles_bad_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {'PATH': os.pathsep.join([tmp, tmp, str(root/'missing')])}):
                p = root/'FreshProbeXYZ.EXE'
                self.assertNotIn('freshprobexyz', _windows_names())
                p.write_bytes(b'not executed')
                self.assertIn('freshprobexyz', _windows_names())
                p.unlink()
                self.assertNotIn('freshprobexyz', _windows_names())

    def test_actual_path_lookup_and_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ('rea_probe.exe' if os.name == 'nt' else 'rea_probe')
            with patch.dict(os.environ, {'PATH': tmp}):
                self.assertIsNone(resolve_executables(['rea_probe'])['rea_probe'])
                p.write_bytes(b'not executed')
                p.chmod(0o700)
                self.assertEqual(Path(resolve_executables(['rea_probe'])['rea_probe']), p)
                p.unlink()
                self.assertIsNone(resolve_executables(['rea_probe'])['rea_probe'])

    def test_detected_frontend_does_not_mean_adapter_available(self):
        def detect(names):
            return {n: '/tools/r2' if n == 'r2' else None for n in names}
        with patch('rei_rea.registry.resolve_executables', side_effect=detect):
            result = tool_doctor()
        tool = next(t for t in result['tools'] if t['id'] == 'radare2')
        self.assertTrue(tool['installed'])
        self.assertFalse(tool['adapter_available'])
        self.assertEqual(result['static_adapters_available'], 0)
