# Reference: architecture overview

What the repository is made of and how data flows through it, on one page,
with links into the gate-checked indexes for every detail. Where this page and
an index disagree, the index wins: [program-index](../../program-index.md) and
[component-index](../../component-index.md) are checked against the tree by
`scripts/check-index.sh` on every CI run; this page is not.

Audience: a developer new to the repository, and anyone deciding where a
change belongs before opening the code.

Rolle: Entwickler · Sprache: EN · Stand: 2026-09-16

## The core rule in one sentence

**Two planes, one repo: `m3c-tools` fills the memory, `skillctl` governs the
agent skills that act on it**, and the trust plane stays pure Go while the
capture plane is allowed cgo and macOS-only features.

## The capture pipeline

ER1 is the personal knowledge server every capture flows into: an external
HTTP service (aims-core), not built in this repo, that stores multimodal
observations; `pkg/er1` is its client
([requirements](../../old/requirements-er1-integration.md),
[service-index](../../service-index.md#external-dependency-er1--aims-core)).
The core flow, as `CLAUDE.md` states it and the packages implement it:

```
transcript.API.Fetch(videoID)        -> FetchedTranscript (snippets)
impression.CompositeDoc.Build()      -> composite text
transcript.Fetcher.FetchThumbnail()  -> JPEG bytes
er1.Upload(config, payload)          -> ER1 server
er1.Queue.Add(entry)                 -> JSON retry queue, on failure
```

Three properties carry the design:

1. **Stdlib-only core.** `pkg/transcript`, `pkg/er1` and `pkg/impression` use
   only the Go standard library; external dependencies (menuet, portaudio)
   stay in POC and desktop layers (`CLAUDE.md`, "Zero external deps").
2. **No YouTube API key.** `pkg/transcript` is a complete port of
   youtube-transcript-api on YouTube's InnerTube API (the internal API the
   YouTube clients themselves use, so no official key is needed); the port
   surface is preserved in [go-rewrite-plan](../../old/go-rewrite-plan.md)
   (historical).
3. **ER1 wants all three fields.** Uploads are multipart with
   `transcript_file_ext`, `audio_data_ext`, `image_data`; the client sends
   placeholder audio or image when the real one is absent (`pkg/er1`).

## The trust plane

`skillctl` gives every agent skill a verifiable identity and a lifecycle:
author, pack, sign, admit, attest, verify or install, use, audit, revoke
(admit publishes a signed bundle into a registry; attest is a reviewer's
signed governance verdict over the same digest). The
chain verifies offline; no hosted authority sits in the verification path
(head of [Manual: skillctl](../referenz/manual-skillctl.md), threat model in
[THREAT_MODEL.md](../../../THREAT_MODEL.md)). The library lives under
`pkg/skillctl/` with the sibling packages `skillbundle` and `skillgate`;
[component-index, section F](../../component-index.md#f-skillctl-trust-subsystem-pkgskillctl--siblings)
carries the gated package list and count.

## Entry points and services

Measured on 2026-09-16 (`ls cmd/`): fourteen entry points under `cmd/`. The
canonical, gate-checked table is the [program-index](../../program-index.md);
the short version:

| Group | Binaries |
|---|---|
| Product CLIs | `m3c-tools` (capture, plus the macOS menu bar app), `skillctl` (trust) |
| Demo and simulation | `skillctl-demo` (offline CISO demo), `skillctl-sim` (scenario corpus against the real binary) |
| Repository gates | `docaudit`, `verbaudit`, `exitaudit`, `structural`, `release-evidence` |
| Reference POCs | `poc-menubar`, `poc-recorder`, `poc-transcript`, `poc-whisper` |
| Cognitive runtime | `thinking-engine` (SPEC-0167), run as a service |

What stays running (thinking-engine, the two MCP servers: stdio processes
speaking the Model Context Protocol, which exposes tools to Claude Code, the
menu bar app, the skillctl container) is the
[service-index](../../service-index.md); the
package-level responsibilities are the
[component-index](../../component-index.md), including section G for the
`internal/thinking/*` packages.

## Conventions a change must respect

| Convention | Source |
|---|---|
| Both CLIs parse `os.Args` by hand; no cobra, no flag package. Follow the `cmdTranscript()` pattern | `CLAUDE.md`, "CLI flag parsing" |
| A new skillctl verb is REGISTERED in [CLI-VERBS](../referenz/CLI-VERBS.md) before it is implemented; `verbaudit` turns CI red otherwise | CLI-VERBS.md, decided 2026-09-04 |
| Exit codes are contract: the register row, the manual's `Exit:` line and `pkg/skillctl/exitcode` must agree; `exitaudit` checks all three | CLI-VERBS.md, "Columns" |
| Tests live in `e2e/`; there are no package-level unit tests | `CLAUDE.md`, "Build & Test Commands" |
| Public plane ships code, private plane keeps reasoning; cross-references by ID only (SPEC-NNNN) | [CONTENT-TOPOLOGY.md](../../../CONTENT-TOPOLOGY.md) |

## Where to go next

- Build, test and the gates: [developer setup](getting-started.md)
- Every command and flag: [Manual: m3c-tools](../referenz/manual-m3c-tools.md),
  [Manual: skillctl](../referenz/manual-skillctl.md)
- What works on which OS: [PLATFORM-DIFFERENCES](../referenz/PLATFORM-DIFFERENCES.md)
- Historical design notes that still explain code:
  [go-rewrite-plan](../../old/go-rewrite-plan.md),
  [spec-plaud-er1-sync](../../old/spec-plaud-er1-sync.md),
  [requirements-er1-integration](../../old/requirements-er1-integration.md)
