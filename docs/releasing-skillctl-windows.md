---
layout: default
title: Releasing skillctl (Windows rollout runbook)
---

# Releasing skillctl — Windows rollout runbook

Operational runbook for the KuP **skillctl Windows-Rollout**. M1 (green windows-gate +
signed release path) and M2 (PowerShell one-click installer + docs + smoke) landed via
**PR #87** (merged to `master`). This page captures the remaining **human-gated** steps to
publish the signed `skillctl/v0.3.1` release and to dry-run it on Windows.

> Branch note: `master` is the default/active branch. Cut tags against `origin/master` by
> its exact hash — this checkout is shared and the working copy may sit on a feature branch.
> Pushing tags/branches that touch `.github/workflows/**` needs **SSH** (the HTTPS OAuth
> token lacks `workflow` scope): `git push git@github.com:kamir/m3c-tools.git <ref>`.

## Step 1 — done (M1/M2, PR #87)
- `cmd/m3c-tools/plaud_dev_test.go` constrained to `//go:build darwin` → **windows-gate green**.
- `tools/skillctl-install.sh` `RELEASE_BASE` default raised to `skillctl/v0.3.1`.
- `tools/skillctl-install.ps1` (cosign-primary, fail-closed) + release-workflow wiring +
  `scripts/skillctl-quickstart-windows.ps1` + `skillctl-windows-smoke.yml`.
- One-liners in `README.md` + `docs/quickstart-skillctl.md`, served from raw `master`.

## Step 2 — cut + promote `skillctl/v0.3.1`

```bash
cd /path/to/m3c-tools
git fetch origin master

# Tag the EXACT merged master head by ref (NOT the working copy — shared tree).
git tag -a skillctl/v0.3.1 \
  -m "skillctl v0.3.1 — signed Windows release + PowerShell one-click installer" \
  origin/master

# Push the tag via SSH — this fires .github/workflows/skillctl-release.yml.
git push git@github.com:kamir/m3c-tools.git skillctl/v0.3.1

# Wait for the keyless-signed build (5 binaries + SHA256SUMS + cosign bundle +
# install.ps1/.sh + SBOM), then inspect its DRAFT assets:
rid=$(gh run list --workflow=skillctl-release.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run watch "$rid" --exit-status
gh release view skillctl/v0.3.1 --json assets -q '.assets[].name'

# Publish the draft:
gh release edit skillctl/v0.3.1 --draft=false
```

> ⚠️ **Do not pass `--latest`.** It would move the `releases/latest` pointer off the product
> release (v2.10.0) and break the manual zip/tarball URLs + the interim stopgap. The signed
> one-liners pin the explicit `skillctl/v0.3.1` tag, so they don't need it. Once published,
> `irm …/skillctl-install.ps1 | iex` verifies + installs from this release.

## Step 3 — re-confirm the cosign pin

```bash
# sigstore's official checksum must match install.ps1's $COSIGN_SHA256:
curl -fsSL https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign_checksums.txt \
  | grep 'cosign-windows-amd64.exe$'
#   expect: a2ac24e197111c9430cb2a98f10a641164381afb83df036504868e4ea5720800  cosign-windows-amd64.exe
grep -n 'COSIGN_VERSION\|COSIGN_SHA256' tools/skillctl-install.ps1
```
Match → done. To move to a newer stable cosign, bump both `$COSIGN_VERSION` and
`$COSIGN_SHA256` in `tools/skillctl-install.ps1`.

## Step 4 — Windows dry-run

**(a) CI smoke — works now (from-source build on `windows-latest`):**
```bash
gh workflow run skillctl-windows-smoke.yml --ref master
sleep 5
gh run watch $(gh run list --workflow=skillctl-windows-smoke.yml --limit 1 --json databaseId -q '.[0].databaseId') --exit-status
```

**(b) Real Windows PowerShell — the true acceptance (after Step 2 publishes):**
```powershell
# 1) one-click install — verifies cosign provenance + SHA-256, installs to %LOCALAPPDATA%\Programs\skillctl:
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/tools/skillctl-install.ps1 | iex

# 2) open a NEW terminal (PATH was updated), then:
skillctl version        # -> skillctl/v0.3.1

# 3) walk the packaged lifecycle smoke (keygen -> pack -> sign -> verify -> trust -> tamper):
$q = "$env:TEMP\skillctl-qs.ps1"
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-quickstart-windows.ps1 -OutFile $q
powershell -ExecutionPolicy Bypass -File $q
```

**Interim (unsigned, works today — before Step 2):** see the interim block in
[quickstart-skillctl.md](quickstart-skillctl.md) — it pulls the current product-release zip
(`skillctl-windows-amd64.zip` → `skillctl.exe`) without provenance verification.

## Next milestones
- **M3** — acceptance `.ps1` track: install / trust / verify / skill-install / **revoke**,
  PASS/FAIL report.
- **M4** — team-work Windows↔M4/Intel: publish → pull → trust → use → audit against the self
  registry.

## Optional maintenance follow-ups (from the PR #87 CI triage)
- Bump the CI Go toolchain to **1.26.6+** (`ci.yml` + `setup-go`) to clear the `govulncheck`
  stdlib CVEs (`GO-2026-6218` net/url, `GO-2026-6091` html/template, …).
- Fix `pkg/menubar/image_darwin.go:87` — `// go:embed` (extraneous space) is an ineffective
  directive (silent no-op embed), which likely undermines the menubar BUG-0192 icon embed.
- Consider pinning the release workflow's third-party actions to commit SHAs (currently
  mutable tags) to fully back the keyless-provenance claim.
