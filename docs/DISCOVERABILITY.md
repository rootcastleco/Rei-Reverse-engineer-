# Repository discoverability and publication checklist

The GitHub About panel is **repository metadata**, not a field inferred from `README.md`. The canonical description, homepage, and Topics are stored in [`../.github/repository-metadata.json`](../.github/repository-metadata.json). README badges and Python package keywords complement those settings but do not replace them.

## Apply the metadata

**Using the GitHub UI (no token needed):**

1. Open `https://github.com/rootcastleco/Rei-Reverse-engineer-` as a repository administrator.
2. Click the gear icon beside **About** on the main repository page.
3. Paste the `description`, `homepage`, and all `topics` from `.github/repository-metadata.json`.
4. Save. Refresh and confirm the Topics chips are visible and link to corresponding GitHub topic pages.

**Using the included CLI (local machine):**

```bash
python scripts/sync_github_metadata.py      # preview; no network or token required
# In a shell with a properly scoped GitHub token already configured:
python scripts/sync_github_metadata.py --apply
```

For `--apply`, set `GH_TOKEN` or `GITHUB_TOKEN` in the local process environment. Do not commit, paste, or print the token. A GitHub token must have the permissions needed to update repository properties and topics. GitHub App installations that only grant Contents write access might be insufficient. The script uses GitHub's REST API with explicit timeouts and verifies the values returned by GitHub. It **replaces** the current Topics list with the metadata file's Topics; review it before applying.

## Readiness checklist

- [ ] Main branch contains a working package, documentation, and tests. A README without its referenced code is not a completed release.
- [ ] About description, URL and Topics match `.github/repository-metadata.json`.
- [ ] README Quick start runs from a fresh clone.
- [ ] GitHub Actions has run the Linux, macOS and Windows test matrix on the published commit.
- [ ] License link resolves to the existing MIT LICENSE file.
- [ ] All linked documentation and twelve skill directories resolve.
- [ ] A release tag is made only after CI and packaging are verified, not merely because the README displays `v0.1.0`.
- [ ] A concise GitHub release note states implemented and missing capabilities.
- [ ] Optional: create a 1280 × 640 social preview with original Rootcastle artwork; confirm display before public promotion.

## Search intent without keyword stuffing

Use accurate phrases in natural documentation: reverse-engineering workbench, binary analysis, static artifact triage, Model Context Protocol (MCP), digital forensics, Android APK investigation, firmware inspection, Electron IPC, SHA-256 evidence ledger, and agent skills. Avoid claiming actual Ghidra, Frida, JADX, or malware sandbox integration until those adapters have passed tests.

A GitHub Topic is not a Git tag. The `topics` field improves search classification. Version tags such as `v0.1.0` identify immutable releases and require a separate release gate.
