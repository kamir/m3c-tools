# skillctl v0.1.0-kup — KuP Berlin training cut

Released: 2026-05-07T08:22:14Z
Source:   /Users/kamir/wt/spec-0189/s2-integration (370e766)

## What's in the box

This is the **first end-user-facing cut** of `skillctl` for the KuP Berlin
Skill-Manager training cohort. It ships:

- The full SPEC-0188 trust-chain CLI: `pack`, `keygen`, `sign`, `verify-sig`,
  `trust`, `install`, `verify`, `attest`.
- The SPEC-0189 inventory CLI: `scan`, `report`, `diff`, `seal`, `audit`,
  `review`, `browse`, `consolidate`, `sync-usage`, `import`.
- The SPEC-0195 awareness bridge: `awareness sync`, `awareness verify`,
  `awareness reset`.
- The SPEC-0196 intent declaration: `intent declare`.

## Install

```bash
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.1.0-kup/install.sh | bash
```

The installer auto-detects OS/arch (darwin · linux · windows × amd64 · arm64),
verifies SHA-256, drops the binary into `$HOME/.local/bin/skillctl`.

## Manual download

| OS / Arch | Asset |
|---|---|
| macOS (Apple Silicon) | `skillctl-darwin-arm64` |
| macOS (Intel) | `skillctl-darwin-amd64` |
| Linux (amd64) | `skillctl-linux-amd64` |
| Linux (arm64) | `skillctl-linux-arm64` |
| Windows (amd64) | `skillctl-windows-amd64.exe` |

Verify checksums against `SHA256SUMS` before running.

## Documentation

- **User manual**: USER-MANUAL.pdf (in the release assets)
- **CLI reference**: SKILLCTL-MANUAL.pdf (in the release assets)
- **Combined handbook**: KuP-skill-manager-handbook.pdf
- **Source docs**: `PROJECTS/Skill-Manager/USER-MANUAL.md` in [m3c-tools-maintenance](https://github.com/kamir/m3c-tools-maintenance)

## Known gaps (read before training)

- Author-side `propose` (SPEC-0194) is drafted, not in the dispatcher yet — use `pack` + `sign` + the registry HTTP endpoint manually until it lands.
- `audit` Phase 2 (full verdict UX with cleanup) is in flight — Phase 1 surface (scan + per-skill verdict) is what's wired today.
- SPEC-0201 `import-public`/`-list`/`-policy lint` and SPEC-0202 `run`/`invoke-replay` are documented but not in this binary cut.

## Verifying the release

The KuP demo `demo/kup-training/run-all.sh` walks every claim in the user manual
end-to-end and asserts a valid skill installs, an invalid skill fails, and a
post-install edit is detected. Re-run on any host to verify the binary behaves
as documented.

