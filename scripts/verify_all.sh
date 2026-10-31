#!/usr/bin/env sh
set -eu
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/generate_catalog.py
python -m compileall -q src/rei_rea
