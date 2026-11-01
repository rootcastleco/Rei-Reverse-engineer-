"""Audited optional providers. Discovery does not imply installation or execution."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import shutil
from .registry import run_static_adapter

@dataclass(frozen=True)
class Provider:
    id: str
    executable: str
    homepage: str
    version_hint: str
    inspect_adapter: str | None = None

PROVIDERS: tuple[Provider, ...] = (
    Provider('ghidra', 'analyzeHeadless', 'https://github.com/NationalSecurityAgency/ghidra', 'distribution metadata'),
    Provider('radare2', 'rabin2', 'https://github.com/radareorg/radare2', 'rabin2 -v', 'radare2'),
    Provider('rizin', 'rz-bin', 'https://github.com/rizinorg/rizin', 'rz-bin -v', 'rizin'),
    Provider('lief', 'python', 'https://github.com/lief-project/LIEF', 'importlib.metadata; no execution'),
    Provider('llvm', 'llvm-readobj', 'https://llvm.org/', 'llvm-readobj --version', 'llvm-readobj'),
    Provider('jadx', 'jadx', 'https://github.com/skylot/jadx', 'jadx --version'),
    Provider('apktool', 'apktool', 'https://apktool.org/', 'apktool --version'),
    Provider('binwalk', 'binwalk', 'https://github.com/ReFirmLabs/binwalk', 'binwalk --version'),
    Provider('unblob', 'unblob', 'https://github.com/onekey-sec/unblob', 'unblob --version'),
    Provider('frida', 'frida', 'https://frida.re/', 'frida --version'),
    Provider('angr', 'python', 'https://github.com/angr/angr', 'importlib.metadata; no execution'),
    Provider('qemu', 'qemu-system-x86_64', 'https://www.qemu.org/', 'qemu-system-x86_64 --version'),
)

def list_providers() -> dict:
    items = []
    for p in PROVIDERS:
        resolved = shutil.which(p.executable) if p.executable != 'python' else None
        items.append({'id': p.id, 'homepage': p.homepage, 'executable': p.executable,
                      'path_detected': bool(resolved), 'resolved_executable': resolved,
                      'adapter_supported': bool(p.inspect_adapter), 'version_hint': p.version_hint,
                      'execution_mode': 'opt-in-static-adapter' if p.inspect_adapter else 'discovery-only',
                      'version_verified': False, 'license_verified': False,
                      'e2e_verified': False, 'bundled': False})
    return {'providers': items, 'provider_count': len(items),
            'warning': 'PATH detection is not installation, version verification, licensing or end-to-end integration.'}

def inspect_provider(provider_id: str, target: str | Path, *, allow_external: bool = False, timeout: float = 12) -> dict:
    provider = next((p for p in PROVIDERS if p.id == provider_id), None)
    if provider is None:
        raise ValueError('Unknown provider')
    if provider.inspect_adapter is None:
        raise ValueError('Discovery only: no reviewed static adapter')
    result = run_static_adapter(provider.inspect_adapter, target, allow_external=allow_external, timeout=timeout)
    return {'provider': provider.id, 'integration': 'opt-in-static-adapter', 'result': result,
            'warning': 'External parsers can have vulnerabilities. Use OS sandboxing for untrusted samples.'}
