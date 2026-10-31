# REI REA coding-agent instructions

1. Read README, `docs/SPEC.md`, `docs/THREAT_MODEL.md` and existing tests before modifying public behavior.
2. Do not import or vendor third-party binary analysis engines without version, provenance, license and explicit change approval.
3. Keep one authoritative registry (`scripts/generate_catalog.py` -> bundled JSON). Differentiate cataloged, PATH-detected, adapter-supported and end-to-end-verified.
4. Read-only target inspection is the default. Never execute an untrusted target, arbitrary shell string, live probe or firmware flash. Dynamic analysis requires scoped authorization and isolation.
5. Preserve evidence identity and limitations (complete vs bounded; source refs and confidence). Do not call decompiler output original source.
6. Implement new capabilities via provider adapters, with contracts and regression tests before enabling by default.
7. Run `PYTHONPATH=src python -m unittest discover -s tests -v`, validate all skills and include tool version/OS in test evidence. Do not label pending remote CI green.
8. Prefer reversible changes, keep branch PRs scoped, and avoid writing customer or proprietary binary samples to this public repository.
