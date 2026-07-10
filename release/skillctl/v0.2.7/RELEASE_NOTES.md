# skillctl v0.2.7 — hygiene, hardening & observability

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

> Builds on **v0.2.6** (trust-chain convergence). This release lands the
> **SPEC-0251 §5 hygiene floor + SPEC-0255 gate observability** — the binaries are
> now built CVE-free, the CI enforces supply-chain gates, and the gate finally
> keeps a record. **No breaking changes.** Recommended upgrade.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.7/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.7 bash
```

## What changed

- **Patched toolchain — 14 → 0 reachable CVEs.** govulncheck found the prior
  releases' binaries carried **14 reachable Go-stdlib CVEs** (crypto/x509,
  html/template, …); the build moved to **go1.26.4**, which clears all of them.
  These v0.2.7 binaries are built on the patched stdlib.
- **Supply-chain gates in CI** — `govulncheck` (blocks on reachable CVEs) and
  `gitleaks` (full-history secret scan) now gate every push; `dependabot.yml`
  keeps deps + actions current.
- **`skillctl gate-stats` — gate observability (SPEC-0255).** Every gate decision
  (PreToolUse hook + SessionStart sweep) is now appended to an advisory
  `~/.claude/skillctl/gate-audit.jsonl`; `gate-stats [--since 168h|YYYY-MM-DD]
  [--json]` summarises decisions, top blocked skills, and the hook cache-hit rate.
  The log is **fire-and-forget telemetry, never a trust input** — a logging
  failure provably cannot change a gate decision (decision-invariance is tested).
- **Exit-code single source of truth (SPEC-0251 §5).** Guard tests pin the 10–19
  ladder to `pkg/skillctl/exitcode`; drift fails CI. (Codified the SPEC-0198
  exit-17 overload: data-source-denied **and** author-identity-revoked share 17.)
- **Zero `//nolint:unused`** — the four dead WIP symbols were removed; the
  `unused` linter is a real enforcer again. CI (lint, unit, `-race` security
  suite, govulncheck, gitleaks, builds) + the Windows Gate are all green.

`skillctl version` prints the stamped tag; SPEC-0246 `publish --share-room` /
`room share|unshare` and the SPEC-0247 load gate carry forward unchanged.

## Provenance
Binaries are checksummed (`SHA256SUMS`) and the manifest is ed25519-signed
(`SHA256SUMS.sig`) by the skillctl **release key** (separate from skill-author
keys). Verify against the pinned public key:

- `skillctl-release.pub` (also at `INFRA/skillctl-release.pub` in the repo)
- K-release fingerprint: `sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2`

```sh
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
```
