# Release flow

How a new version of **m3c-tools** and **skillctl** is cut, built, signed and
published. This is the operational runbook; for the Windows‑signing specifics see
[releasing-skillctl-windows.md](releasing-skillctl-windows.md).

> **TL;DR**: a release is **tag‑driven**. Pushing a version tag to GitHub is the
> trigger; CI does the multi‑platform build, signing and publishing. There is no
> `VERSION` file: the tag *is* the version (GoReleaser reads `{{.Version}}`).

---

## Two independent release lines

The repo ships two products from one tree; each has its **own** version series and
its **own** workflow. Never assume they move together.

| Line | Tag pattern | Workflow | Produces |
|------|-------------|----------|----------|
| **Product** (`m3c-tools` + bundled binaries) | `vX.Y.Z` | [`.github/workflows/release.yml`](../.github/workflows/release.yml) | macOS universal (arm64+amd64), Linux amd64/arm64, Windows amd64, the NSIS `M3C-Tools-Setup.exe`, `checksums.txt` + **cosign bundle** + **SLSA provenance** |
| **skillctl** (the signed trust CLI) | `skillctl/vX.Y.Z` | [`.github/workflows/skillctl-release.yml`](../.github/workflows/skillctl-release.yml) | the 4 platform `skillctl` binaries + `.exe`, `install.sh`/`install.ps1`, `SHA256SUMS` + **cosign bundle** + **ed25519 fallback sig**, **CycloneDX SBOM**, SLSA provenance: published as a **draft** |

Example from the last cut: product `v2.11.0` and `skillctl/v0.4.0` were released
from the **same** commit but as two separate tags.

---

## Choosing the version bump

Semver level is **derived from the commits**, not guessed, by
[`scripts/derive-bump.sh`](../scripts/derive-bump.sh) (Conventional Commits):

| Commit signal (highest wins) | Bump |
|------|------|
| `feat!:` / `fix!:` / a `BREAKING CHANGE:` trailer | **major** |
| any `feat:` | **minor** |
| everything else | **patch** |

Line count is **not** a signal. A one‑line feature is still a `minor`; a
thousand‑line behaviour‑preserving refactor is still a `patch`. **major is never
issued automatically** ("breaking" is a statement about callers, which no diff can
see); `make release` aborts and demands the explicit `make release-major`.

> This rule exists because the Fleet kill‑switch (a feature) once shipped as a
> patch (`v2.8.1`) under a hard‑wired `release-patch`. The commits already carried
> `feat:`: the information was there; now it is used.

---

## The canonical path: tag `origin/master` by hash

**Recommended, and what the maintainers actually use.** Because working copies
drift onto feature branches and worktrees, do **not** let a script tag "the
current branch". Tag the exact reviewed commit on `master`, by hash:

```bash
git fetch origin
HASH=$(git rev-parse origin/master)          # the reviewed, green commit

# Product line:
git tag  v2.12.0 "$HASH"
git push origin v2.12.0

# skillctl line (independent version):
git tag  skillctl/v0.5.0 "$HASH"
git push origin skillctl/v0.5.0
```

The tag push starts the matching workflow. Watch it:

```bash
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

### Pre‑flight (before you tag)

The gates below run inside `make release`, but the **tag‑push path bypasses them**
, which is how `v2.11.0` skipped the docs check. Run them yourself on the commit
you are about to tag, and rely on the in‑CI gates (below) as the backstop:

```bash
make ci                 # vet · lint · test-unit · build
make code-review        # build · vet · tests · secrets · TODO · dead-code · sizes · err-handling · version · deps
make check-docs         # documentation ↔ implementation consistency
./tools/boundary-gate.sh
goreleaser check        # validate .goreleaser.yml before relying on it
```

---

## The scripted path: `make release` (local, convenience)

```bash
make release            # derive-bump → code-review → check-docs → release-auto
make release-minor      # force a level (also: release-patch / release-major)
```

`make release` runs `code-review` + `check-docs` first, then
[`scripts/release.sh`](../scripts/release.sh) bumps, tags and creates the release.

> ⚠️ **`scripts/release.sh` operates on your WORKING COPY.** It will
> `git add -A && git commit` any dirty files, `git push` the **current** branch,
> and create the release with **local macOS‑only** assets. Run it **only** from a
> clean checkout of `master`: **never** from a feature branch or a worktree, or
> you will publish the wrong branch. When in doubt, use the tag‑by‑hash path
> above and let CI build every platform. The CI workflow then enriches the same
> release with the full signed multi‑platform artifacts.

---

## What CI signs (the trust story)

Both workflows sign **keyless** with cosign via GitHub OIDC, **no long‑lived key
in the repo**, and each **verifies its own signature in‑job** (a broken signing
step yields a draft/failure, never an unsigned release):

- **Product `v*`** → `cosign sign-blob checksums.txt` → `checksums.txt.cosign.bundle`;
  SLSA subjects → `multiple.intoto.jsonl`, gated by `slsa-verifier`.
- **skillctl `skillctl/v*`** → `cosign sign-blob SHA256SUMS` →
  `SHA256SUMS.cosign.bundle` (identity `…/skillctl-release.yml@refs/tags/skillctl/v…`);
  **plus** an ed25519 `SHA256SUMS.sig` against the pinned `skillctl-release.pub`,
  so users without cosign still verify via the fallback baked into `install.sh`;
  **plus** a CycloneDX SBOM.

Consumers verify with (product example):

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
slsa-verifier verify-artifact <asset> --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/kamir/m3c-tools
```

---

## After the workflow goes green: manual steps

1. **Publish the skillctl draft.** `skillctl-release.yml` publishes as a *draft* for
   a sanity check. Promote it:
   ```bash
   gh release edit skillctl/v0.5.0 --draft=false
   ```
2. **Decide the "Latest" badge.** GitHub's *Latest* flag is **global**, not
   per‑line: publishing the skillctl draft flips it onto skillctl. Pin it to the
   product release if that is what users should land on:
   ```bash
   gh release edit v2.12.0 --latest
   ```
3. **Bump the install‑script pins** (a security step: see below).
4. **Verify the download surface**: `gh release view v2.12.0 --json assets -q '.assets[].name'`.

### Bumping the pinned install one‑liners

The `README.md` and `docs/quickstart-skillctl*.md` one‑liners pin the bootstrap
scripts to an **immutable commit hash** (not `master`), plus the expected SHA‑256
of each script: a TOFU defence, since `master` could be rewritten to swap the
script *and* its inner pins at once. On **each** signed release, bump the commit
**and** both hashes together:

```bash
NEWPIN=$(git rev-parse origin/master)
shasum -a 256 tools/skillctl-install.sh tools/skillctl-install.ps1
# → update the pinned commit + both SHAs in README.md and docs/quickstart-skillctl.md
```

---

## Gotchas (learned the hard way)

- **Tag by hash, from `master`.** Working copies drift; a script that tags "the
  current branch" is a foot‑gun. See the canonical path above.
- **`.github/workflows/**` needs SSH to push**: the HTTPS OAuth token lacks the
  `workflow` scope. Push workflow edits over an SSH remote.
- **The macOS universal build depends on the owned‑infra PortAudio mirror**
  (`portaudio-vendor` release asset). If the upstream host is down, the mirror +
  pinned SHA‑256 keep the build green; do not point it back at a third party.
- **GitHub Actions storage is tight (~0.5 GB).** CI artifacts have a 7‑day
  retention and the policy is to keep only the **latest** release's
  goreleaser‑binaries. Clean older ones so the account budget is not exhausted.
- **Artifacts must be wired in BOTH** `.goreleaser.yml` **and** the release
  workflow: a binary added to one but not the other silently goes missing.

---

## Rollback

Tags are the source of truth, so a bad release is undone by removing the tag and
release and re‑cutting:

```bash
gh release delete v2.12.0 --yes
git push origin :refs/tags/v2.12.0    # delete the remote tag
git tag -d v2.12.0                     # and the local tag
# fix, then re-tag the corrected commit
```
