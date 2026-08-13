# m3c-tools v2.10.0 — durable Plaud capture + server-side transcription

**Release date:** 2026-08-13
**Tag:** `v2.10.0` (m3c-tools product line; `skillctl` ships alongside under the same bundle)
**Predecessor:** v2.9.0

This release makes **Plaud** capture durable and hands-off, and makes
transcription of un-transcribed recordings a **server-side** default so the
processing queue drains on your own host. Binaries for macOS (Intel + Apple
Silicon), Windows, and Linux are published on the GitHub Release.

> **Platform note.** The new `plaud dev` durable-OAuth workflow and server-side
> transcription control are **macOS today** (they live in the darwin build). The
> Windows/Linux binary keeps the legacy `plaud auth/list/sync` surface. See
> `docs/setup-target-devices.md` and `docs/PLATFORM-DIFFERENCES.md`.

## Added
- **Durable Plaud developer-API capture — `plaud dev`** (SPEC-0341). Uses the
  official `@plaud-ai/mcp` OAuth token that **auto-refreshes** (no daily
  re-login), stored in `~/.plaud/tokens-mcp.json`.
  - `plaud dev list [--preview] [--limit N]` — numbered, newest-first listing
    with sync status, first words of the transcript, and the ER1 doc-id if
    already synced.
  - `plaud dev sync <#|ID|N-M> … | --all | --limit N` — sync selected recordings;
    `--dry-run`, `--force` (re-sync), `--tags a,b`, `--whisper` (local override).
  - `plaud dev status` — server-side transcription-queue view (active status
    breakdown + failed count + per-item progress), so the processing host's
    queue draining is visible.
- **MCP login driver** — `node tools/plaud-mcp-login.mjs` mints the durable OAuth
  token in one Google sign-in; after that it auto-refreshes.
- **Server-side transcription as the default** (SPEC-0341 §8c). Recordings that
  Plaud/Pocket have **not** transcribed are uploaded with `DoTranscribe=true` so
  Whisper runs **server-side** (aims-core SPEC-0111 queue) on your processing
  host. `--whisper` is an opt-in **local** override; `PLAUD_TRANSCRIBE_MODE`
  (`queue`|`lazy`|`off`) tunes the un-transcribed path.
- **skillctl online-fallback state gate** (SPEC-0317 R-1.4 P2) — opt-in
  strictly-local hot path, state-gated online fallback.

## Changed
- **One shared sync truth.** `plaud dev` and the menubar Plaud Sync now share the
  same ledger — the local `plaud://<id>` tracking DB **plus** the SPEC-0117 server
  mapping — so both tools agree on what is already in ER1 (no more "eigene
  Wahrheit"). Legacy `plaud-dev` ledger rows are migrated on first run.
- The menubar **Plaud Sync** menu item now drives the durable dev path
  (auto-refresh, shared core), reporting per-disposition progress
  (`plaud`/`queued`/`whisper`/`audio`).

## Fixed
- **Durable, SSO-safe token acquisition** — self-calibrating token probe
  (harvest candidates → probe `api.plaud.ai` → keep the accepted one), Bearer
  auth, and OAuth-token import. Resolves the `-3900 invalid auth header` regression.
- **`plaud auth mcp` verifies before saving** — no longer clobbers a working
  token with an incompatible one.

## Security
- Dev-path security-review follow-ups: **redirect/SSRF guard** re-validates every
  hop and restricts audio downloads to allowed S3 hosts; **account-id derived from
  the JWT `sub`** (stable across refresh, not the rotating token hash); **atomic**
  token-file writes; terminal-escape stripping on rendered fields.
- `ER1_API_KEY` remains an `X-API-KEY`-only credential — never logged, never
  committed. Plaud's OAuth `client_secret` is not hardcoded (public PKCE client).

## Validation
- Full offline gate green on the release commit: `go vet ./...`, all `pkg/…` +
  `cmd/…` package tests, and the offline e2e suite (`make test-unit`).
- Cross-platform builds validated locally before tagging: darwin/arm64 (native),
  **darwin/amd64 (Intel, CGO + universal PortAudio)**, windows/amd64, linux
  amd64+arm64, and a full `goreleaser` snapshot.

## Install
See **`docs/setup-target-devices.md`** for the Intel-Mac & Windows setup +
operations runbook, and **`docs/QA-target-device-setup.md`** for the on-device
acceptance test (QA Strecke). Download artifacts from the
[latest GitHub Release](https://github.com/kamir/m3c-tools/releases/latest);
verify against `checksums.txt`.
