# Local release fallback signature

[Deutsch](release-fallback.de.md) | [English](release-fallback.en.md)

The normal release workflow creates a CI draft. The local helper adds an Ed25519
fallback signature for installers without Cosign, using **existing CI bytes**.
It does not build a checkout, create tags, upload assets, generate a runbook, or
publish to THOH. A dirty or unrelated checkout cannot supply release binaries.
Run the helper from a trusted reviewed checkout; it is not a sandbox for malicious
local code or tools running as the operator.

```sh
tools/skillctl-release.sh skillctl/v0.5.1
```

Run this operator helper on Linux or macOS with Python 3 (POSIX file-size limits).
This does not change the supported customer CLI platforms, including Windows.
Other prerequisites: authenticated `gh` release/tag read access, trusted
preinstalled `cosign`, `slsa-verifier` (CLI contract checked against v2.7.1), and
OpenSSL with Ed25519 support. Missing tools or evidence cause failure; no tools
are installed. A CI draft/release for the exact tag must already contain the five
standard binaries, `SHA256SUMS`, `SHA256SUMS.cosign.bundle`, and exactly one
`*.intoto.jsonl` provenance asset. Unsupported formats fail closed. Asset metadata and downloaded sizes must match;
binaries are limited to 128 MiB each, metadata to 4 MiB each and declared assets
to 512 MiB total. The download subprocess also has a 128 MiB per-file write limit.
Binary hashing streams data instead of loading whole binaries into memory.
A copy failure removes the output directory created by this invocation.

Before opening `RELEASE_KEY` (default `~/.config/m3c/skill-release.key`), the helper:

1. Validates the tag and resolves its remote commit, including annotated tags.
2. Downloads only the required assets to a private temporary directory.
3. Verifies the exact manifest with Cosign against the exact tag identity
   `https://github.com/kamir/m3c-tools/.github/workflows/skillctl-release.yml@refs/tags/<tag>`
   and issuer `https://token.actions.githubusercontent.com`.
4. Requires exactly five canonical checksum entries and verifies every binary.
5. Runs SLSA verification for every binary with the repository, exact source tag,
   and CI's pinned v2.1.0 generic builder. It consumes only successful verifier
   `--print-provenance` output: the signed v0.2 statement must bind the exact
   subject names/digests, source commit, release workflow, environment commit and tag.
6. Rechecks the remote tag and the manifest bytes.

It then signs the untouched downloaded manifest and verifies the signature against
`INFRA/skillctl-release.pub`, independently pinned to raw Ed25519 SHA256 fingerprint
`5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2`.
A different signing key fails. Existing output and symlinked output parents are
refused. Local results go to `release/<tag>/`; upload remains a separate reviewed
operation. `THOH_PUBLISH` has no effect on this helper. Generate runbooks separately
with `tools/skillctl-runbook.sh`.

These checks establish artifact origin and byte consistency within the configured
trust anchors. They do not establish vulnerability freedom, current customer
approval, release-evidence completeness, or a permanent freeze of a mutable GitHub
tag after the final read. CI promotion/evidence gates remain separate.

Offline tests use mocked GitHub/Cosign/SLSA responses and real temporary Ed25519
keys/OpenSSL. They prove orchestration, rejection paths and local signature checks;
they do not prove live Sigstore/SLSA verification of an actual release.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/skillctl_release_fallback_test.py
```
