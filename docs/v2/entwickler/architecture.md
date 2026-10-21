# Reference: architecture overview

Sprachen / Languages: [Deutsch](architecture.de.md) | [English](architecture.md)

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
([client implementation](../../../pkg/er1/),
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

1. **Focused Go core.** `pkg/transcript`, `pkg/er1` and `pkg/impression` implement
   capture and document processing. Credential storage and private-file permissions
   use explicit platform helpers; Windows ACL handling uses `golang.org/x/sys/windows`.
   GUI and audio dependencies (menuet, portaudio) stay in the desktop layers.
2. **No YouTube API key.** `pkg/transcript` is a complete port of
   youtube-transcript-api on YouTube's InnerTube API (the internal API the
   YouTube clients themselves use, so no official key is needed); the API
   is implemented in [pkg/transcript](../../../pkg/transcript/).
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
| Product CLIs | `m3c-tools` (capture, plus the macOS menu bar app), `skillctl` (trust), `secretctl` (the secret register, SPEC-0438) |
| Demo and simulation | `skillctl-demo` (offline CISO demo), `skillctl-sim` (scenario corpus against the real binary) |
| Repository gates | `docaudit`, `verbaudit`, `exitaudit`, `structural`, `release-evidence` |
| Reference POCs | `poc-menubar`, `poc-recorder`, `poc-transcript`, `poc-whisper` |

What stays running (the two MCP servers: stdio processes speaking the Model
Context Protocol, which exposes tools to Claude Code, the menu bar app, the
skillctl container) is the [service-index](../../service-index.md); the
package-level responsibilities are the
[component-index](../../component-index.md).

## Conventions a change must respect

| Convention | Source |
|---|---|
| m3c-tools parses arguments by hand; skillctl also uses the standard-library `flag` package. Follow the surrounding command implementation | [m3c-tools commands](../../../cmd/m3c-tools/), [skillctl commands](../../../cmd/skillctl/) |
| A new skillctl verb is REGISTERED in [CLI-VERBS](../referenz/CLI-VERBS.md) before it is implemented; `verbaudit` turns CI red otherwise | CLI-VERBS.md, decided 2026-09-04 |
| Exit codes are contract: the register row, the manual's `Exit:` line and `pkg/skillctl/exitcode` must agree; `exitaudit` checks all three | CLI-VERBS.md, "Columns" |
| Package tests sit next to their implementation; end-to-end tests live in `e2e/` | [Developer setup](getting-started.md#part-b-test) |
| Public plane ships code, private plane keeps reasoning; cross-references by ID only (SPEC-NNNN) | [CONTENT-TOPOLOGY.md](../../../CONTENT-TOPOLOGY.md) |

## Where to go next

- Build, test and the gates: [developer setup](getting-started.md)
- Every command and flag: [Manual: m3c-tools](../referenz/manual-m3c-tools.md),
  [Manual: skillctl](../referenz/manual-skillctl.md)
- What works on which OS: [PLATFORM-DIFFERENCES](../referenz/PLATFORM-DIFFERENCES.md)
- Capture clients: [ER1](../../../pkg/er1/), [Plaud](../../../pkg/plaud/),
  [Pocket](../../../pkg/pocket/); commands and configuration are in the
  [m3c-tools manual](../referenz/manual-m3c-tools.md)
