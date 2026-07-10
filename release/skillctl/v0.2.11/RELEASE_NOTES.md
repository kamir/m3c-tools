# skillctl v0.2.11

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.11/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.11 bash
```

## What's new
- `skillctl publish --share-room <label>` — map a bundle into a SPEC-0096
  co-learning room at admit time (repeatable; `$SKILL_SHARE_ROOMS`).
- `skillctl room share|unshare <skill> --room <label>` — back-fill / remove the
  room mapping on already-published bundles.
- `skillctl version` — prints the stamped release tag.

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
