# skillctl v0.2.8 — keyless provenance (cosign/OIDC)

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

> First skillctl release **built and signed entirely in CI** with **keyless
> Sigstore cosign + GitHub OIDC** (no long-lived signing key) — plus a SLSA build
> provenance attestation. The pinned-ed25519 track is retained so existing
> installs keep verifying. No code changes vs v0.2.7; this is the provenance
> upgrade (SPEC-0253). Recommended upgrade.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.8/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.8 bash
```

`install.sh` is now **dual-track**: when `cosign` is present it verifies the
keyless bundle against the release workflow's OIDC identity; otherwise it falls
back to the pinned-ed25519 signature. A present-but-invalid cosign bundle
fails closed (no downgrade). `SKILLCTL_REQUIRE_COSIGN=1` forces cosign-only.

## Provenance — two tracks

**Keyless (cosign + GitHub OIDC):**
```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# SLSA build provenance:
gh attestation verify skillctl-linux-amd64 --repo kamir/m3c-tools
```

**Pinned ed25519 (transition fallback):**
```sh
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
```
- K-release fingerprint: `sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2`

Built on go1.26.4 (CVE-free stdlib). Carries forward all v0.2.4–v0.2.7 hardening.
