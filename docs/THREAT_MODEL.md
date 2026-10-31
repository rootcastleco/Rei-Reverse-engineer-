# Threat model and security controls

**Assets**: analyst host, lab credentials, proprietary input binaries, sensitive strings, case evidence, toolchain integrity, production devices and user authorization.

| Threat | Control implemented | Residual risk / follow-up |
| --- | --- | --- |
| Malicious executable silently launched | No target execution; no runtime tools reachable from MCP/web | A user can deliberately run a third-party parser with CLI opt-in; isolate first |
| Shell command injection | `shell=False`; fixed in-code static adapter arguments; absolute target paths | A malicious or shadowed executable on PATH remains possible; pin signed binaries later |
| Archive traversal / zip bombs | ZIP entries listed only; no unpack; path traversal and ratio warnings | ZIP metadata parsing itself uses Python `zipfile`; isolate adversarial samples |
| Oversized files / CPU exhaustion | Header and archive listing bounds, signals/diff 16 MiB cap, adapter timeouts | Full-file SHA-256 time is proportional to file size; impose host quotas |
| Exposure of credentials embedded in strings | No strings in default signals; no automatic uploads | Explicit opt-in returns raw bytes as text; redact before sharing with model or third party |
| MCP prompt-to-host file access | Local stdio only, no direct code execution; explicit artifact path args | A connected agent may read arbitrary paths permitted to its user; scope the MCP client/OS sandbox |
| HTTP CSRF and remote access | Loopback-only, GET-only, no mutation endpoints, no arbitrary file endpoint | A local browser could query catalog; never expose via public tunnel without additional auth design |
| Evidence record alteration | SHA-256 chain and explicit rehash command | Any attacker with full write access can recompute the chain; signatures + external timestamps not implemented |
| Wrong RE conclusion | Distinguish observed/inferred/unknown, encode coverage limits, parity tests planned | Decompiler inaccuracies, packers and obfuscation remain unresolved |
| Commercial tool license violations | No third-party binaries shipped; catalog metadata distinguishes discovery | Analyst must separately review license, seats, usage and any trial restrictions |
| Supply-chain compromise | No auto installers; no dependency downloads at runtime; planned pinned providers | GitHub CI actions need pinning to immutable SHAs and dependency lock/attestation before regulated use |

### Authorization

All analysis should be confined to software, firmware and recordings the operator owns or is explicitly allowed to inspect. Dynamic instrumentation, live traffic acquisition, hardware programming, security testing against third-party services and license boundary changes require separate scoped authorization and suitable isolation. The design places no artificial limit on the **number of future adapters or skills** but retains authorization, resource and security boundaries.

### Disclosure and incident handling

Do not commit binaries, credentials, customer captures or raw memory to the public repo. Redact logs. For a confirmed issue, preserve the target SHA-256, test fixture, affected version and reproduction steps without customer secrets. Keep the legacy path unchanged until tests pass; a provider can be disabled by removing its explicit invocation, with no database migration.
