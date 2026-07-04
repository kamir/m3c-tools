---
layout: default
title: Illustration Prompt — m3c-tools
---

# Illustration prompt kit

Paste one of these into your image model of choice (Midjourney, DALL·E, Ideogram, Flux,
Nano Banana, etc.) to generate a hero/cover illustration for the README and docs site.
The **story to convey**: two halves of one system — a pipeline that turns the messy world
(video, audio, screenshots, voice) into structured *memory*, and a *trust plane* that
signs and governs the agent skills acting on that memory. Sovereign, offline, yours.

---

## 1. Primary hero image (recommended)

> A sleek, modern technical illustration in a clean isometric style. On the **left**, a
> "capture pipeline": stylized streams of raw signals — a YouTube play button, a sound
> waveform, a screenshot frame, a microphone — flowing rightward and being distilled into
> neat, glowing memory cards stacked in a personal vault. On the **right**, a "capability
> plane": a translucent horizontal layer where small autonomous agent figures reach toward
> the memory vault, but each agent's hand passes through a glowing verification gate marked
> with a **checkmark, a key, and a signature seal** — some pass (green), one is stopped
> (amber). A thin luminous line connects both halves, labeled implicitly by flow, not text.
> Palette: deep indigo and slate background, electric teal and cyan accents, warm amber for
> the "denied" gate, soft white highlights. Subtle grid floor, faint circuit textures,
> volumetric glow. Confident, trustworthy, high-tech but human-scale — not corporate stock.
> Crisp vector-adjacent shading, 4k, generous negative space at top for a title.
> **Aspect ratio 16:9. No text, no logos, no watermarks.**

---

## 2. Minimalist emblem (for a badge / favicon / social card)

> A minimalist emblem combining two motifs into one mark: a **memory node** (a rounded
> square containing three stacked cards or layers) fused with a **shield-and-key** for
> trust. Single-weight linework, geometric, balanced, suitable at small sizes. Two-tone:
> teal on deep navy, or monochrome line art on transparent. Modern open-source project vibe.
> **1:1 square. No text.**

---

## 3. Conceptual "planes" diagram (for the docs / pillar page)

> A calm, editorial isometric diagram of horizontal translucent planes stacked in depth,
> like glass shelves floating in dark space. From bottom to top: an **event stream** plane
> (flowing ordered dots), a **memory** plane (glowing cards), a **reasoning** plane (small
> agent glyphs), a **provenance/audit** plane (an immutable ledger ribbon), and a
> **capability** plane at the front (signed keys and verification checkmarks gating access).
> Compute arrows point *down toward the data*, not up. Thin cyan connective light between
> planes. Muted, sophisticated palette: charcoal, indigo, teal, a single warm accent.
> Editorial infographic quality, lots of breathing room. **Aspect ratio 16:9. No text labels.**

---

## 4. Dark-mode README banner (wide)

> A wide, cinematic banner: on a near-black background, a horizontal river of luminous data
> particles flows left-to-right, gradually condensing from chaotic raw signals into orderly
> glowing memory blocks, then passing through a single elegant **verification gate** (a ring
> with a keyhole and a checkmark) before reaching a serene personal "vault" on the right.
> Electric teal and cyan light, deep shadows, subtle lens bloom, a sense of calm control.
> Minimal, premium, developer-tool aesthetic. **Aspect ratio 3:1 (wide banner). No text.**

---

## Style & negative-prompt cheatsheet

**Add for consistency:** `isometric, clean vector shading, volumetric glow, deep indigo +
teal + cyan palette, subtle circuit texture, premium developer-tool aesthetic, high detail,
4k`

**Negative / avoid:** `no text, no lettering, no logos, no watermark, no busy clutter, no
cheesy stock-photo people, no cluttered UI screenshots, not skeuomorphic, not neon-overload`

**Tips**
- Keep **negative space at the top** if you'll overlay the project title.
- Generate the emblem (#2) on a transparent background for reuse.
- Ask for `16:9` for the site hero, `3:1` for the GitHub social/banner, `1:1` for the badge.
- If the model renders garbled text, re-run with "no text" emphasized — labels should be
  added later in a vector editor, not baked into the image.

---

## 5. Fact-accurate "ecosystem" infographic (corrected variant)

A first-pass "package manager" infographic looked great but baked in wrong facts
(a `github.com/skillctl/skillctl` URL, a `get.skillctl.dev` installer, and invented
`skillctl search` / `pdf-extract` commands). Use this prompt instead when you want an
infographic that renders **real** text — so it can go in the repo without misleading anyone.

> A polished dark-mode developer infographic for a CLI tool called **skillctl**, the
> trust-and-governance CLI for AI-agent skills. Left column: four labeled feature rows with
> line icons — **Sign** (a key + signature seal), **Verify** (a shield with a checkmark),
> **Install** (a download arrow into a box), **Revoke** (a circular arrow with a stop). Center:
> a realistic macOS-style terminal window titled `skillctl` showing the real command flow —
> `skillctl keygen`, `skillctl pack`, `skillctl sign`, then `skillctl verify-sig ✓ ok (offline)`,
> then `skillctl install my-skill@1.0.0 ✓ installed`. Right column: a small ecosystem diagram —
> a "personal registry (ER1)" node and a "git repos" node feeding into the skillctl hexagon,
> which fans out to "verify → install → use" with a small robot labeled "AI agent". Deep navy
> background, electric teal + violet accents, green for the ✓ success states, single-weight line
> icons, premium open-source aesthetic, generous spacing. **Aspect ratio 16:9.**

**If the model bakes text into the image, it MUST use only these real strings** (everything
else should be "no text"):

- Tool name: `skillctl`  ·  Tagline: *the trust layer for agent skills*
- Real commands only: `keygen`, `pack`, `sign`, `verify-sig`, `trust`, `install`, `verify`,
  `publish`, `pull`, `registry`, `agentid`, `revoke` — **never** `search`, `init`, `build`, `run`.
- Repo URL (footer): `github.com/kamir/m3c-tools`  — **not** `skillctl/skillctl`.
- Install line (if shown): `curl -sL github.com/kamir/m3c-tools/releases/latest/download/skillctl-darwin-arm64.tar.gz | tar xz`
  — **not** `get.skillctl.dev`.
- License (footer, correct): `Apache-2.0`.
- Trust phrasing: *offline-verifiable — no hosted CA in the verification path* (evidence-led, no overclaim).
- Do **not** invent a public skill marketplace or named skills (no `pdf-extract`, `web-search`, `skillhub`).
