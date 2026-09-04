# QA Acceptance Track: m3c-tools v2.10.0 (Target-Device Setup)

**Purpose.** Validate a *fresh* m3c-tools **v2.10.0** install **on the machine it will run on**.
Run this right after checkout/install, on the actual target device.

**Covered targets**

| Icon | Target | GOOS/GOARCH | Release binary |
|------|--------|-------------|----------------|
| 🍎 | Intel Mac (macOS x86_64) | `darwin/amd64` | `m3c-tools` (from the macOS CI/DMG build) |
| 🪟 | Windows PC | `windows/amd64` | `m3c-tools.exe` (from `m3c-tools-windows-amd64.zip`) |

> The macOS binary is a **CGO** build (PortAudio + Cocoa menubar). The Windows/Linux
> binary is **CGO-free** and CLI-only. Several capture features are macOS-only. That
> split is *by design*; the stages below encode it as PASS/FAIL gates so you never
> chase a "missing" feature that was never meant to ship on Windows.

## How to run

- **Automated core:** run the shipped helper and read its summary.
  - 🍎/Linux: `scripts/qa-target-device.sh` (offline by default; `--online` or `QA_ONLINE=1` adds the network stages)
  - 🪟 Windows: `powershell -ExecutionPolicy Bypass -File scripts\qa-target-device.ps1` (`-Online` for network stages)
- **Manual / interactive steps** (menubar launch, live recording) are marked 🖐 and are *not*
  automated, do them by hand and tick the sign-off table.

**Expected noise (not a failure).** Every invocation prints two lines to **stderr**:

```
2026/08/13 11:15:20 [config] profile: <name>
2026/08/13 11:15:20 [auth] device token loaded for user=<id>…
```

These are informational. On a *brand-new* install with no active profile / no linked device,
one or both lines may be **absent**, also fine. Parse **stdout** and **exit codes**, never these lines.

**Secret hygiene.** No step in this track ever prints `ER1_API_KEY` (or any token). The helper
scripts check key *presence* with a quiet grep and never echo the value. Keep it that way.

---

## Stage A: Binary integrity & runs

### A1 · Checksum verification
Verify the downloaded archive/binary against the release `checksums.txt` (sha256).

| | Command | Expected | PASS |
|-|---------|----------|------|
| 🍎 | `shasum -a 256 -c checksums.txt` (in the extracted dir) | `m3c-tools-darwin-amd64…: OK` | line ends `OK`, exit 0 |
| 🪟 | `Get-FileHash .\m3c-tools.exe -Algorithm SHA256` then compare to the `checksums.txt` entry | hash matches the published line | strings equal |

**FAIL → remediation.** Re-download the artifact (partial/corrupt transfer or wrong arch). Never
run a binary whose checksum does not match the release notes for v2.10.0.

### A2 · Version prints a real version
```
m3c-tools version
```
- **Expected stdout:** `m3c-tools 2.10.0 (commit=<hash>, built=<date>)`
- **PASS:** exit 0 **and** the version token is `2.10.0` (not `dev`).
- **FAIL → remediation.** If it prints `dev` you are running a local/unreleased build: install
  the official v2.10.0 artifact. If the command errors, the binary is the wrong platform (see A1).

---

## Stage B: Config present & valid

Configuration is resolved from the first of these that exists (the helper checks all of them):
1. `$M3C_ENV` (explicit override), 2. repo `./.env`, 3. `~/.m3c-tools.env`,
4. the active profile `~/.m3c-tools/profiles/<active-profile>.env`
(🪟 `%USERPROFILE%\.m3c-tools\...`).

### B1 · A config source exists
- **PASS:** at least one of the files above exists.
- **FAIL → remediation.** Copy `.env.example` → `.env` and fill it in, **or** run
  `m3c-tools login` (device-token onboarding, writes a profile), **or** `m3c-tools config create`.

### B2 · `ER1_API_URL` is set: **required**
- **PASS:** a non-comment `ER1_API_URL=<value>` line exists in a config source.
- **FAIL → remediation.** Add `ER1_API_URL=https://onboarding.guide/upload_2` (public) or your
  local `https://127.0.0.1:8081/upload_2`.

### B3 · `ER1_CONTEXT_ID` is set: **required**
- **PASS:** a non-comment `ER1_CONTEXT_ID=<value>` line exists.
- **FAIL → remediation.** Add your context id (e.g. `…___mft`). `m3c-tools login` fills this in
  automatically from the browser callback.

### B4 · `ER1_API_KEY` is set. **Conditional**
- **PASS:** `ER1_API_KEY=<value>` is present **OR** a device token is active (see the doctor
  *Authentication* section: "Bearer token (SPEC-0127)"). With device-token auth the API key is
  *not needed* (`doctor` reports `API key: set but not needed (token active)`).
- **FAIL/WARN → remediation.** If you use API-key auth and neither an API key nor a device token
  is present, run `m3c-tools login` to mint a device token, or set `ER1_API_KEY=…`.

> Do **not** open the config file in a shell that echoes it into a shared log, the key is a secret.

---

## Stage C: Offline self-check (`doctor`)

```
m3c-tools doctor
```
`doctor` prints six sections: **Profile**, **Authentication**, **Config Consistency**,
**Connectivity**, **Plaud**, **Device Pairing**, then a final `Result:` line. It exits **non-zero
if any check fails**, and the *Connectivity* section requires the network.

### C1 · Diagnostics report is produced: **offline-safe, required**
- **PASS (offline):** the command runs and prints the report (the **Config Consistency** section
  appears). Offline, the *Connectivity* section is **expected to fail** and the process exits 1,
  that is acceptable for C1; full connectivity is graded online in **D**.
- **FAIL → remediation.** If `doctor` cannot even produce the Profile/Config sections, the profile
  is broken: run `m3c-tools config list` / `m3c-tools config switch <name>` to select a valid one.

### C2 · Full doctor pass: **ONLINE, required (graded in Stage D run)**
- **PASS:** `doctor` exits **0** and prints `Result: ALL CHECKS PASSED ✓`.
- **FAIL → remediation.** Read the first `✗`/`!` line: it names the failing subsystem
  (DNS / TLS / `/health` / auth endpoint / config conflict) and how to fix it.

---

## Stage D: Online ER1 connectivity  🌐 ONLINE-ONLY

> Only run Stage D/E/F-online with network access. The helper gates these behind `--online` /
> `QA_ONLINE=1` (🪟 `-Online`).

### D1 · `check-er1`
```
m3c-tools check-er1
```
- **Expected stdout (3 lines):**
  ```
  ER1 -> https://…/upload_2 auth=device-token ctx=…___mft timeout=600s ssl=true
  ER1 server: REACHABLE
  Auth check: OK (device token)
  ```
- **PASS:** exit **0**, stdout contains `REACHABLE` **and** `Auth check: OK`.
- **FAIL → remediation.**
  - `UNREACHABLE` → check network/VPN, `ER1_API_URL`, and that the ER1 host is up (`doctor` DNS/TLS lines localize it).
  - `Auth check: FAILED` → token/API-key invalid or expired → `m3c-tools login` (device token) or fix `ER1_API_KEY`.
  - **Transient network blip:** re-run once; the helper reports a clean FAIL + this remediation rather than crashing.

---

## Stage E: Core capture smoke test  🌐 ONLINE-ONLY (E1)

### E1 · Transcript fetch (YouTube InnerTube pipeline)
```
m3c-tools transcript dQw4w9WgXcQ --list
```
- **Expected stdout:** a list of available transcript tracks, e.g.
  `English (en) manual [translatable]` … (one per line).
- **PASS:** exit **0** and at least one track line on stdout.
- **FAIL → remediation.** A YouTube `429` is rate-limiting (the tool degrades gracefully; retry
  later or set `YT_PROXY_URL`). A parse/HTTP error means the InnerTube path is blocked. Check
  network/proxy. Use a video id you know has captions.

### E2 · Whisper presence: **offline, optional (WARN)**
```
m3c-tools setup --check
```
- **Expected stdout:** a `Whisper:` line resolving to a real path, e.g.
  `Whisper: /opt/homebrew/bin/whisper (system, fallback)` (or a venv path).
- **PASS:** a `Whisper:` line points to an installed binary (not `(not installed)` on *every* line).
- **WARN (not a hard FAIL):** whisper absent: only needed for local audio transcription
  (voice notes, `import-audio`). Core transcript + ER1 upload work without it.
- **Remediation.** `m3c-tools setup` builds the venv and installs whisper; or put a `whisper`
  binary on `PATH`. (`setup --check` intentionally exits 1 while the venv is not installed even
  when a system whisper exists: grade E2 on the `Whisper:` line, not on that exit code.)

---

## Stage F: Platform-specific

### 🍎 Intel Mac

#### F-mac-1 · Audio input devices
```
m3c-tools devices
```
- **Expected stdout:** `Audio input devices (N):` followed by one line per device
  (`* MacBook … 1 ch 48000 Hz`).
- **PASS:** exit 0 and at least one device listed. **(Soft: needs PortAudio + an input device.)**
- **FAIL → remediation.** Grant microphone permission to the terminal/app; confirm an input
  device exists in *System Settings → Sound*.

#### F-mac-2 · Live recording  🖐 manual
```
m3c-tools record /tmp/qa-mic-test.wav --duration 3
```
- **PASS:** exit 0, a ~3 s `.wav` is written (16 kHz/16-bit mono).
- **FAIL → remediation.** Same mic-permission / device checks as F-mac-1.
- *Not automated* (records live audio): do it once by hand.

#### F-mac-3 · Menubar app launches  🖐 manual
```
m3c-tools menubar
```
- **PASS:** the "M3C" item appears in the macOS menu bar; the startup banner prints; the menu opens.
- **FAIL → remediation.** Check Accessibility/Screen-Recording permissions; run from a login GUI
  session (not a bare SSH shell). Quit from the menu when done.

#### F-mac-4 · Plaud dev-API reachable  🌐 ONLINE-ONLY, soft
```
m3c-tools plaud dev status
```
- **Expected stdout:** the server-side transcription queue, e.g.
  `Server-side transcription queue: empty: nothing pending, nothing failed. ✅`
- **PASS:** exit 0 and a queue line printed. **(Soft: needs a valid Plaud OAuth token.)**
- **FAIL → remediation.** `m3c-tools plaud auth mcp` (mint the durable OAuth token). Note: the
  Plaud sync API occasionally returns `HTTP 400` transiently. Re-run before failing the device.
- **`plaud dev` is macOS-only.** Do **not** expect it on Windows/Linux.

### 🪟 Windows

#### F-win-1 · Systray/menubar entry present
```
m3c-tools menubar
```
- **PASS:** the system-tray icon appears (cross-platform `systray`), banner prints. 🖐 manual.
- **FAIL → remediation.** Run from an interactive desktop session; check that the tray is not
  hidden in the overflow area.

#### F-win-2 · Legacy Plaud surface present: **required**
The Windows build ships the **legacy** Plaud commands only: `auth`, `list`, `check`, `sync`,
`fix-times`. Verify they are wired:
```
m3c-tools help
```
- **PASS:** `help` lists `plaud auth`, `plaud list`, `plaud check`, `plaud sync`, `plaud fix-times`.
- Live check (🌐 optional): `m3c-tools plaud check` prints a sync-coverage report (exit 0).
- **FAIL → remediation.** Wrong/old binary: reinstall `m3c-tools-windows-amd64.zip` for v2.10.0.

#### F-win-3 · macOS-only features are correctly **unsupported**. Expected-FAIL
These must **not** be treated as PASS on Windows. Expected behavior:

| Command | Expected on Windows | Verdict |
|---------|---------------------|---------|
| `m3c-tools record` | `Error: audio recording requires macOS with PortAudio` (exit 1) | expected-unsupported |
| `m3c-tools devices` | same error (exit 1) | expected-unsupported |
| `m3c-tools screenshot` | `Error: screenshot capture requires macOS` (exit 1) | expected-unsupported |
| `m3c-tools plaud dev …` | not a valid subcommand (legacy plaud only) | expected-unsupported |

- **PASS of the gate:** each command *fails as above*. If any of them *succeeds*, that is itself a
  FAIL (wrong build / unexpected capability).

---

## Acceptance sign-off

Fill in on the target device. Required rows must be **PASS** to accept the install.

| Stage | Check | 🍎 Intel Mac | 🪟 Windows | Required? | Operator note |
|-------|-------|:---:|:---:|:---:|---------------|
| A1 | Checksum verify | ☐ | ☐ | ✅ | |
| A2 | `version` = 2.10.0 | ☐ | ☐ | ✅ | |
| B1 | Config source exists | ☐ | ☐ | ✅ | |
| B2 | `ER1_API_URL` set | ☐ | ☐ | ✅ | |
| B3 | `ER1_CONTEXT_ID` set | ☐ | ☐ | ✅ | |
| B4 | `ER1_API_KEY` set / token active | ☐ | ☐ | ⚠️ cond. | |
| C1 | `doctor` report produced (offline) | ☐ | ☐ | ✅ | |
| C2 | `doctor` full pass (online) | ☐ | ☐ | ✅ 🌐 | |
| D1 | `check-er1` REACHABLE + auth OK | ☐ | ☐ | ✅ 🌐 | |
| E1 | `transcript --list` smoke | ☐ | ☐ | ✅ 🌐 | |
| E2 | whisper present | ☐ | ☐ | ⚠️ opt. | |
| F-mac-1 | `devices` lists inputs | ☐ | n/a | ⚠️ soft | |
| F-mac-2 | `record` writes wav 🖐 | ☐ | n/a | ⚠️ soft | |
| F-mac-3 | menubar launches 🖐 | ☐ | n/a | ⚠️ soft | |
| F-mac-4 | `plaud dev status` 🌐 | ☐ | n/a | ⚠️ soft | |
| F-win-1 | systray launches 🖐 | n/a | ☐ | ⚠️ soft | |
| F-win-2 | legacy `plaud` present | n/a | ☐ | ✅ | |
| F-win-3 | mac-only cmds unsupported | n/a | ☐ | ✅ | |

**Accepted by:** ________________  **Device / OS build:** ________________  **Date:** __________

**Overall verdict:** ☐ ACCEPT ☐ REJECT (attach the `qa-target-device` summary output)
