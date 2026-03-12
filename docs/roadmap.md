---
layout: default
title: Roadmap & Ideas
---

# Roadmap & Ideas

This project is designed to grow. Below is the living roadmap — a place to track ideas, capture impulses, and plan next steps.

## Current state (v1.5)

- [x] Full Go rewrite (from Python) — native macOS binary
- [x] Pure Go transcript library (port of youtube-transcript-api)
- [x] macOS menu bar app (menuet + native Cocoa via cgo)
- [x] Unified Observation Window (3 tabs: Record, Review, Tags)
- [x] 4 capture channels: YouTube (A), Screenshot (B), Impulse (C), Audio Import (D)
- [x] Live VU meter with color-coded audio levels
- [x] Local Whisper integration (subprocess)
- [x] ER1 multimodal upload (image + audio + transcript)
- [x] Offline retry queue with exponential backoff
- [x] ER1 browser login linking (runtime context override)
- [x] YouTube rate limit mitigation (cache, proxy, graceful degradation)
- [x] CLI: transcript fetch, import, schedule, status, cancel
- [x] Pre-release code review + docs consistency check
- [x] GitHub Pages documentation
- [x] macOS .app bundle with icon + Info.plist
- [x] CI pipeline (vet + lint + test + build)
- [x] Draft saving on cancel (~/.m3c-tools/drafts/)
- [x] Tracking DB window with 2 tabs (Tracked Items + Source Files)
- [x] Source Files: checkbox selection, sortable columns, folder path, creation date
- [x] Bulk operations: Transcribe+Upload and Re-process Selected with progress bar
- [x] Re-processing with doc_id reuse for ER1 document overwrite
- [x] YouTube transcript preserved through voice recording (not overwritten by whisper)
- [x] Clipboard-first screenshot: uses existing clipboard image without re-capture
- [x] Optional audio: Store without recording (ER1 gets placeholder audio)
- [x] Configurable timeouts: whisper up to 2h, ER1 upload up to 10min

---

## Completed: Go Rewrite

The full Python-to-Go rewrite is **complete**. The original migration plan and POC validation results are archived in the maintenance repository (`PLAN/go-rewrite-plan.md`).

Key wins over Python version:
- Single static binary (no Python/pip/virtualenv)
- Sub-100ms startup (vs 2-3s for Python)
- Native Cocoa UI via cgo (no Tkinter subprocess hacks)
- In-process audio recording via PortAudio (no PyAudio)
- Proper goroutine concurrency (no GIL)

---

## Completed: ER1 Integration

The ER1 integration is **fully implemented** in Go packages:

- [x] `pkg/er1/` — config, upload, retry queue, reachability check
- [x] `pkg/impression/` — observation types, tag system, composite documents
- [x] `pkg/whisper/` — local Whisper transcription
- [x] `pkg/importer/` — batch audio import from preconfigured folder
- [x] `pkg/menubar/capture.go` — Store/Cancel with draft saving
- [x] ER1 browser login linking with session persistence
- [x] Offline retry queue with exponential backoff

Full requirements are archived in the maintenance repository (`SPEC/requirements-er1-integration.md`).

---

## Future work

### Hardening & quality

- [ ] **Gemini post-processing** — tag-to-prompt pipeline for automated enrichment (R5)
- [ ] **Login callback token validation** — explicit signature/token verification
- [ ] **Encrypted session file** — at-rest encryption for ER1 session
- [ ] **Integration tests for login callback** — callback parsing and URL extraction
- [ ] **Go 1.26.1 upgrade** — fixes 4 stdlib vulnerabilities (GO-2026-4599 through 4602)

### Transcript tools

- [ ] **Batch fetch** — fetch transcripts for a list of video IDs from a file
- [ ] **Export formats** — save transcripts as Markdown, Obsidian notes, or Logseq pages
- [ ] **Transcript search** — full-text search across all stored transcripts
- [ ] **Summary generation** — LLM summarization of transcripts (optional)

### Menu bar enhancements

- [ ] **Quick search** — search transcript history from the menu bar
- [ ] **Global keyboard shortcut** — hotkey to trigger transcript fetch
- [ ] **Auto-detect clipboard** — detect YouTube URLs in clipboard and offer to fetch
- [ ] **Auto-update** — check for new versions on launch

### Infrastructure

- [ ] **Code signing** — sign the .app bundle for Gatekeeper
- [ ] **DMG packaging** — distribute as signed DMG
- [ ] **Homebrew formula** — `brew install m3c-tools`

### Large file refactoring (noted)

These files exceed 2000 lines and could benefit from splitting:
- `cmd/m3c-tools/main.go` (2330 lines)
- `pkg/menubar/observation_darwin.go` (2102 lines)

---

## Impulse capture

A scratchpad for raw ideas and impulses. No commitment, no priority — just capture.

_Use GitHub Issues or edit this page directly to add new impulses._

| Date | Impulse | Status |
|------|---------|--------|
| 2026-03-09 | Create gh-pages documentation site | done |
| 2026-03-09 | ER1 integration — standardize audio-checklist-checker pattern for YT videos | done |
| 2026-03-09 | Impression capture — speak about a video, bundle both transcripts into ER1 | done |
| 2026-03-10 | Pre-release code review gates | done |
| 2026-03-10 | Mein Nutzerkonto menu item (ER1 profile page) | done |
| | Integrate with Obsidian for knowledge management | idea |
| | Channel-level transcript aggregation | idea |
| | Diff two transcripts (e.g., re-uploads, edits) | idea |
| | Webhook/notification when a channel posts new content | idea |
| | Transcript quality scoring (auto-generated vs. manual) | idea |
| | Browser extension for one-click transcript fetch | idea |

---

## Contributing ideas

Have an idea? Capture it:

1. **Quick:** [Open a GitHub Issue](https://github.com/kamir/m3c-tools/issues/new?labels=idea&title=Idea:+) with the `idea` label
2. **Detailed:** Fork, edit `docs/roadmap.md`, and open a PR
3. **Discuss:** Start a [GitHub Discussion](https://github.com/kamir/m3c-tools/discussions) in the Ideas category

---

Back: [Menu Bar App](menubar-app) | [Home](/)
