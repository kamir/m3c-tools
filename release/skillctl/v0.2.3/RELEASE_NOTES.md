# skillctl v0.2.3

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.3/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.3 bash
```

## What's new — SPEC-0247 Claude Code trust gate (load-time verification)
- `skillctl verify-hook` — a Claude Code **PreToolUse(Skill)** gate: re-verifies a
  skill at load time and **denies** (exit 2) on a bad signature / digest mismatch.
- `skillctl verify --all [--quarantine] [--json] [--budget]` — a **SessionStart sweep**
  that verifies every installed skill and (with `--quarantine`) moves trust-failures
  out of `~/.claude/skills/` before the agent loads them. Follows symlinks.
- **Network-free verification + content-binding**: re-binds the extracted on-disk
  `SKILL.md` to the signed `.skb` so an edited body is caught as a digest mismatch.
- **self/ER1 (pull) format**: pull-installed skills (`.m3c-provenance.json`) are
  verified offline — content-binding + governance floor + trust-root fingerprint.
- Offline **verdict cache** (HMAC-keyed by content digest) for a fast, offline gate.
- Cross-platform: gate tests validated on the windows-latest CI runner.
- Carries forward SPEC-0246 `publish --share-room` / `room share|unshare`;
  `skillctl version` prints the stamped release tag.

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
