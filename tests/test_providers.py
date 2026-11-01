import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from rei_rea.providers import list_providers, inspect_provider
from rei_rea.mcp import invoke_tool, TOOLS
from rei_rea.cli import main

class ProviderTests(unittest.TestCase):
    def test_inventory(self):
        v = list_providers()
        self.assertEqual(v['provider_count'],12)
        self.assertEqual(len({p['id'] for p in v['providers']}),12)
        self.assertTrue(all(not p['bundled'] and not p['e2e_verified'] and not p['license_verified'] for p in v['providers']))

    def test_unsafe_provider_rejected(self):
        with self.assertRaises(ValueError):
            inspect_provider('frida', '/tmp/s', allow_external=True)
        with self.assertRaises(ValueError):
            inspect_provider('nonexistent', '/tmp/s', allow_external=True)

    def test_static_optin_required(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';p.write_bytes(b'123')
            with self.assertRaises(PermissionError):
                inspect_provider('radare2', p)

    def test_mcp_discovery_only(self):
        self.assertEqual(invoke_tool('rei_rea_providers', {})['provider_count'],12)
        self.assertFalse(any(t['name']=='rei_rea_provider_inspect' for t in TOOLS))

    def test_cli(self):
        self.assertEqual(main(['providers','list']),0)

    def test_fixed_subprocess_args(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';p.write_bytes(b'123')
            with patch('rei_rea.registry.shutil.which', return_value='/usr/bin/rabin2'):
                with patch('rei_rea.registry.subprocess.Popen') as pop:
                    pop.return_value.wait.return_value=0
                    result=inspect_provider('radare2',p,allow_external=True)
                    self.assertEqual(pop.call_args.args[0][:2],['/usr/bin/rabin2','-I'])
                    self.assertFalse(pop.call_args.kwargs['shell'])
                    self.assertEqual(result['provider'],'radare2')
