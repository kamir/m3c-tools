# Guide: getting started with m3c-tools

[Deutsch](einstieg.de.md) · [English](einstieg.en.md)

How a user gets from an empty machine to their first capture, and which existing
pages guide them afterwards. This page consolidates the introductory parts of
three English sources
([Quickstart: m3c-tools](quickstart-m3c-tools.md),
[Getting Started](getting-started.md),
[Prerequisites](prerequisites.md)); if they disagree, the docaudit-gated
[manual](../referenz/manual-m3c-tools.md) takes precedence.

Audience: anyone who wants to use m3c-tools. Part A is sufficient if you only
need the finished program; Part B covers building from source on macOS;
Part C points to the tutorials and menu bar app.

Role: user · Language: EN · Updated: 2026-09-16

## The core rule in one sentence

**Get a green result from `m3c-tools doctor` before trusting your first capture:**
the command checks the profile, authentication, DNS, TLS and ER1 endpoints.
Everything else builds on that result.

## Which route is yours

| Situation | Route | Section |
|---|---|---|
| I want to use the tool on any platform | Prebuilt release binary | Part A |
| I want the macOS menu bar app with microphone and screenshots | Source build with cgo | Part B |
| I want to understand the tool first | Read, then Part A | [Manual: m3c-tools](../referenz/manual-m3c-tools.md) |
| My machine has neither git nor Go | Only required for Part B | [Prerequisites](prerequisites.md) |

## Part A: the prebuilt binary (all platforms)

1. Download the binary from the [current release](https://github.com/kamir/m3c-tools/releases/latest).
   Copyable platform commands for macOS arm64/amd64, Linux amd64 and Windows are in
   [Quickstart: m3c-tools, section 1](quickstart-m3c-tools.md#1-install).

2. Check that the binary responds:

   ```bash
   m3c-tools version
   m3c-tools help
   ```

3. Connect to ER1 using the guided setup. The wizard asks for the server URL,
   browser login, API key and default tags, then writes them to `~/.m3c-tools.env`:

   ```bash
   m3c-tools setup
   ```

   To configure it manually instead, copy `.env.example` to `~/.m3c-tools.env`.
   The three required variables are `ER1_API_URL`, `ER1_API_KEY`, `ER1_CONTEXT_ID`
   ([full reference](../referenz/manual-m3c-tools.md#configuration-reference)).

4. Obtain the diagnostic result:

   ```bash
   m3c-tools doctor
   ```

5. Make your first capture. A transcript does not require ER1:

   ```bash
   m3c-tools transcript dQw4w9WgXcQ
   ```

   A complete observation, including transcript, thumbnail and your comment,
   goes to ER1 with `m3c-tools upload <video-id> --impression "..."`.
   Variants are in
   [Quickstart: m3c-tools, section 4](quickstart-m3c-tools.md#4-your-first-capture).

## Part B: build from source on macOS (menu bar app)

Prerequisites: git and Go 1.25 or later (`go.mod` requires 1.25.0), plus the
Homebrew packages for cgo and audio. Platform details are in
[Prerequisites](prerequisites.md).

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make deps          # Homebrew- und pip-Abhaengigkeiten, nur beim ersten Mal
make install       # baut, erzeugt M3C-Tools.app, installiert CLI und App
make permissions   # oeffnet die macOS-Berechtigungs-Panes nacheinander
make menubar       # startet die Menueleisten-App
```

[Getting Started](getting-started.md) explains exactly what `make install` does,
including the app bundle, paths and Info.plist, and how to uninstall it.
[Menu Bar App](menubar-app.md) describes the app, its four capture channels and
the Observation Window.

## Part C: where to go next

| I want to ... | Page | Language |
|---|---|---|
| Practice, with real exit codes as evidence | [Tutorial: Katas and Test Ride](tutorial-katas-und-test-ride.en.md) | EN |
| Use my own skills on several machines | [Tutorial, scenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md) | EN |
| Sign my first skill, reviewed by a second person | [Tutorial, scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md) | EN |
| Look up every command and flag | [Manual: m3c-tools](../referenz/manual-m3c-tools.md) | EN |
| Import audio folders in batches | [Audio Import & Tracking](audio-import-tracking.md) | EN |
| Connect a recorder, Plaud or Pocket | [Quickstart: m3c-tools, section 6](quickstart-m3c-tools.md#6-capture-devices-optional) | EN |
| Check what is missing on my platform | [Platform differences](../referenz/PLATFORM-DIFFERENCES.md) | EN |

If something goes wrong, consult the error table in
[Quickstart: m3c-tools, Troubleshooting](quickstart-m3c-tools.md#troubleshooting)
and the Troubleshooting section of the [manual](../referenz/manual-m3c-tools.md#troubleshooting).
