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

## Release approval: who signs off, and before what

A tag push is the point of no return: it starts a workflow that builds, signs and
publishes. Everything in this section happens **before** it.

### The machine half is already a blocking gate

The **SPEC-0406** two-party acceptance test runs in
[`skillctl-release.yml`](../.github/workflows/skillctl-release.yml) as
`acceptance-gate`, a matrix over **macOS and Windows**, placed *before* the build
so a failure stops the release instead of annotating a finished artifact. It runs
`TestAcceptance_TwoParty` (T01..T15) plus the twin rehearsal scripts
[`scripts/skillctl-acceptance.sh`](../scripts/skillctl-acceptance.sh) and
[`scripts/skillctl-acceptance.ps1`](../scripts/skillctl-acceptance.ps1);
[`ci.yml`](../.github/workflows/ci.yml) runs the Unix twin on every push, so the
gate is not first exercised at tag time.

What it cannot see: whether **two people on two machines** compared a key
fingerprint over a second channel (SPEC-0246 R6.3, Phase 0). That is a human act,
and no CI job can observe it. The gate covers the machine half of SPEC-0406, and
the workflow's own gate record says exactly that.

### The human half: the second pair of eyes

| # | Step | Who | What is checked | Where the result is recorded |
|---|------|-----|-----------------|------------------------------|
| 1 | Code review | someone who did not write the commits | the diff on `master` since the previous tag | the approving review on the pull request |
| 2 | Fingerprint out of band (Phase 0) | the consumer, on their own machine | the author public key fingerprint, read back over a second channel | the [acceptance checklist](acceptance-skillctl-lifecycle.md#9-handover-checklist-for-erics-team) |
| 3 | Consumer lane, Part B | the consumer, on their own machine | the **published** artifacts, never a local build | exit codes of `pull --install --trust-mode`, `verify`, `audit` |

For the skillctl line step 3 has a natural home: `skillctl-release.yml` publishes a
**draft**. Do not run `gh release edit skillctl/vX.Y.Z --draft=false` before step 3
has been performed against that draft's artifacts. Promoting the draft *is* the
sign-off, so treat it as one and not as a formality.

Record the outcome in the release body, so the evidence sits next to the artifacts
it is about:

```bash
gh release view skillctl/v0.5.0 --json body -q .body > /tmp/notes.md
cat >> /tmp/notes.md <<'EOF'

## Acceptance (SPEC-0406)
- Second person: <name>, machine: <os/arch>, date: <YYYY-MM-DD>
- Phase 0 fingerprint compared out of band: yes/no, channel: <...>
- Part B exit codes: pull=0, verify=0, audit=0
EOF
gh release edit skillctl/v0.5.0 --notes-file /tmp/notes.md
```

The product line (`v*`) has no draft stage today, so its equivalent is: cut it,
perform step 3 against the published assets, and use [Rollback](#rollback) if it
fails.

### Break-glass: the solo path

**This repository has exactly one account with write access.** Steps 1 and 3 can
therefore often not be filled by a different person, and naming a second reviewer
who does not exist would be a decoration, not a control. The solo path is
allowed, and it is **break-glass**:

- it is a deliberate act, never the silent default;
- the release body carries the same `## Acceptance (SPEC-0406)` heading, naming
  who released, which of the three steps had no second person, and why;
- the missing step is caught up afterwards. Either a second person performs it and
  the result is appended under that heading, or the release is rolled back.

> Written down because the alternative was already the practice: the last five
> merged pull requests carried zero reviews, and `v2.9.0` was published from a
> laptop. A solo path nobody documents is indistinguishable from a broken one.

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

## The scripted path: `make release` (derive the level, tag, and stop)

```bash
make release            # derive-bump → code-review → check-docs → tag origin/master
make release-minor      # force a level (also: release-patch / release-major)
```

`make release` runs `code-review` + `check-docs`, derives the bump level, and then
[`scripts/release.sh`](../scripts/release.sh) **tags `origin/master` by hash and
pushes the tag**. It prints the commit it is about to tag, plus its subject and
author, and asks for a confirmation; `--yes` skips the prompt, and without a
terminal it refuses rather than guessing. This is the canonical path above with
the version arithmetic done for you.

It deliberately does **not** build, package, upload an asset, create a release, or
commit anything: publication is `release.yml` alone. A modified tracked file makes
it refuse, because it tags `origin/master` and your local changes would not be in
the release either way.

> **Why it used to be dangerous.** Until this change the script ran
> `git add -A && git commit` over the working copy, built a macOS binary and a DMG
> on the laptop, and uploaded both with `gh release create --latest`. The
> `checksums` job in `release.yml` hashes only the CI artifacts (`*.tar.gz`,
> `*.zip`, `*.exe`), so those two assets landed in neither `checksums.txt` nor the
> SLSA subjects. `v2.9.0` still shows it: `m3c-tools` and `M3C-Tools-2.9.0.dmg`
> are release assets, and its `checksums.txt` lists neither of them.

### The macOS DMG is not a release asset

`make dmg` still builds `build/M3C-Tools-<version>.dmg` locally, and that is now
all it is: a development convenience. It is not published, because an asset CI
does not build cannot be covered by `checksums.txt`, the cosign signature or the
SLSA provenance, and an uncovered asset on a signed channel is worse than a
missing one: a user cannot tell the two apart at the download page.

Restoring it as a download is a CI job, not a script call. What it would take,
deliberately **not** done here:

1. a step in the existing `build-macos` job (already `macos-latest`, already with
   PortAudio) that runs `make build-app` plus `scripts/make-dmg.sh` and uploads
   the DMG as a workflow artifact. It would be arm64-only unless the two darwin
   binaries are merged into a universal one with `lipo` first;
2. `*.dmg` added to **both** globs in the `checksums` job (`checksums.txt` **and**
   the base64 SLSA subjects) and to the loop in the `verify` job, or the DMG ships
   unattested again, which is the defect this change removes;
3. the asset added to the `files:` list of the `release` job;
4. and the part that is not YAML: the `.app` bundle is neither codesigned nor
   notarised (both are open items in [roadmap.md](roadmap.md)), so a downloaded
   DMG is quarantined by Gatekeeper. Shipping an unsigned DMG through a signed
   channel trades one trust problem for another; an Apple signing identity and a
   notarisation step have to exist first.

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
script *and* its inner pins at once.

**This is automated.** Publishing a `skillctl/v*` release fires
[`.github/workflows/pin-bump.yml`](../.github/workflows/pin-bump.yml), which
resolves the tag, rewrites the pin and both digests, verifies the result and
opens a pull request. Your job is to review and merge that PR, not to edit the
hashes by hand.

> It fires on **published**, not on the tag push: the release workflow cuts a
> *draft*, and a pin must not move to a release nobody has released yet.

If you ever need it by hand, or want to check whether the docs are current:

```bash
./scripts/bump-install-pins.sh skillctl/vX.Y.Z --check   # exit 1 = stale
./scripts/bump-install-pins.sh skillctl/vX.Y.Z           # rewrite
./scripts/check-install-pins.sh                          # the gate
```

**Never `git rev-parse <tag>` on its own.** An annotated tag resolves to a tag
object, and `raw.githubusercontent.com` serves commits only. Pinning a tag
object once put a 404 behind every published install one-liner, on Windows and
Unix alike, until a user reported it from the field (BUG-0215). Both scripts
above resolve `^{commit}`, which is why the mistake is no longer reachable.

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
