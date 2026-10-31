# Upstream REA synchronization

Rootcastle REI REA is a **separate Python workbench**. Its upstream reference is [morluto/rea](https://github.com/morluto/rea), a distinct Node.js/TypeScript-oriented reverse-engineering project. These codebases are **not** drop-in interchangeable.

## How the update works

- Git submodule path: `upstream/rea` (gitlink pinned to an exact upstream commit).
- Source: `https://github.com/morluto/rea.git`; the repository remains owned by its upstream maintainers.
- Daily GitHub Actions schedule (04:17 UTC), plus optional manual `workflow_dispatch`.
- A changed upstream `main` commit creates/updates a **review PR** on `automation/upstream-rea`.
- The action updates only the upstream gitlink; no automatic merge, dynamic execution, dependency installation, or upstream-to-Rootcastle source replacement.
- The action runs Rootcastle's unit tests before opening or refreshing a PR. Due to GITHUB_TOKEN workflow-event suppression, it is **not sufficient to assume all PR CI has run**.
- GitHub-hosted scheduled workflows can be delayed or disabled following repository inactivity; check the Actions history regularly.

## Review and integration

1. Review the pinned source commit, change diff, its license, lockfiles, submodules, releases and security advisories.
2. Run independent REI REA CI and verify security-sensitive functionality.
3. Test compatibility through an explicit version-aware adapter; updating the submodule alone **does not integrate upstream features** into the Python CLI or MCP.
4. Merge the update PR only after review. To roll back, revert the gitlink commit and repeat CI.

## Manual setup

```bash
git clone https://github.com/rootcastleco/Rei-Reverse-engineer-.git
cd Rei-Reverse-engineer-
git submodule update --init upstream/rea
git -C upstream/rea rev-parse HEAD
```

`git submodule update` downloads the pinned source tree but does not build or execute it. **Do not run unknown binaries as part of an update.**

## If automation does not open a PR

Ensure GitHub Actions are enabled on the **default branch**, that the workflow has permission to read upstream public repository metadata, and that the repository's Actions settings allow workflows to create pull requests. The `GITHUB_TOKEN` must be allowed to create PRs. The workflow fails rather than silently marking a sync successful when this permission is missing.

## Release guarantees

- **Synced:** upstream source revision pointer after a reviewed merge.
- **Not automatically synced:** API bindings, analyzer implementations, tests for upstream tools, third-party binaries, or ChatGPT skill installations.
- **Rollback:** revert the upstream gitlink change, then test. Do not rewrite history on `main`.
