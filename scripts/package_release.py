#!/usr/bin/env python3
"""Deterministically package source and manifest; never include targets, caches or secrets."""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=Path('/mnt/data/REI-REA-Workbench-v0.1.0.zip')
OMIT={'.git','__pycache__','.egg-info','dist','build','.pytest_cache','.rei-cases'}
items=[]
for p in sorted(ROOT.rglob('*')):
    if p.is_file() and not any(part in OMIT or part.endswith('.egg-info') for part in p.relative_to(ROOT).parts):
        rel=p.relative_to(ROOT).as_posix()
        items.append((p,rel))
manifest={"version":"0.1.0","project":"Rootcastle REI REA","files":{rel:hashlib.sha256(p.read_bytes()).hexdigest() for p,rel in items}}
OUTPUT.parent.mkdir(exist_ok=True,parents=True)
with zipfile.ZipFile(OUTPUT,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p,rel in items:
        entry=zipfile.ZipInfo('rei-rea/'+rel,date_time=(2026,10,31,0,0,0))
        entry.compress_type=zipfile.ZIP_DEFLATED
        entry.external_attr=0o100644 << 16
        z.writestr(entry,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    entry=zipfile.ZipInfo('rei-rea/RELEASE-MANIFEST.json',date_time=(2026,10,31,0,0,0))
    entry.compress_type=zipfile.ZIP_DEFLATED
    z.writestr(entry,json.dumps(manifest,indent=2,sort_keys=True)+'\n')
print(json.dumps({'path':str(OUTPUT),'files':len(items),'bytes':OUTPUT.stat().st_size,'sha256':hashlib.sha256(OUTPUT.read_bytes()).hexdigest()},indent=2))
