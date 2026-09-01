# skillctl v0.2.4 — security release

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

> ⚠️ **Supersedes v0.2.3.** This release fixes the 7 P0 findings from the
> 2026-06-10 security audit (SPEC-0251). **Upgrade from v0.2.3** — its binaries
> and installer contained the pre-fix code.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.4/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.4 bash
```

## Security fixes (SPEC-0251 P0 remediation)
- **Governance-verdict forgery (HIGH):** the self/ER1 pull now verifies the
  attestation **and** revocation event envelope signatures before trusting a
  bundle's governance level — a forged "green" attestation can no longer pass
  the green floor.
- **Decompression-bomb caps** (100 MiB · 10k files · `O_EXCL` · symlink refusal)
  on the self/ER1 extractor **and** the per-invocation gate content check.
- **Load-time gate (SPEC-0247):** content-binding is now enforced on **every**
  managed verify path, and a sidecar skill with no stashed `.skb` **fails
  closed** — "edited body → exit 10" now holds everywhere.
- **Path-traversal** install write blocked (bundle-name sanitisation).
- **Local servers** (config editor / review / browse) bind **127.0.0.1** only,
  with a loopback Host-header guard (were `0.0.0.0`, secret-bearing).
- **This installer pins the release-key fingerprint** and fails closed on
  mismatch (a poisoned origin can no longer swap key+sig+binary).
- **Windows signing unblocked** — key perm-check is GOOS-guarded; `signing` is
  now exercised on the windows-latest CI gate.

Carries forward SPEC-0246 `publish --share-room` / `room share|unshare`;
`skillctl version` prints the stamped tag.

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
