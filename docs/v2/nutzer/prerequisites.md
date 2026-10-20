---
layout: default
title: Prerequisites
---

# Prerequisites: what a machine needs before the first run

Two tools, on every platform: **git** and **Go 1.25 or newer**. Everything else is
optional and named as such below. If `git --version` and `go version` both answer, skip to
[Quickstart: skillctl](quickstart-skillctl.md).

---

## Windows (PowerShell)

### The two required tools

Windows 10 (1809+) and Windows 11 ship `winget`. One line each, no manual download:

```powershell
winget install --id Git.Git    -e --source winget
winget install --id GoLang.Go  -e --source winget
```

**Then reload your PATH.** A `winget` install writes the machine PATH, but your open
PowerShell session still holds the old copy, so `git` will look missing until you either
open a new window or run:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path','User')
git --version
go version
```

`go version` must print **1.25.0 or higher**; that is what `go.mod` requires.

### If `winget` is not there

`winget` comes with the **App Installer** package. Install it from the Microsoft Store, or
use one of these instead:

```powershell
# Scoop: per-user, no admin rights at any point
irm get.scoop.sh | iex
scoop install git go

# Chocolatey: machine-wide, needs an elevated shell
choco install git golang -y
```

Or download the installers by hand: [git-scm.com/download/win](https://git-scm.com/download/win)
and [go.dev/dl](https://go.dev/dl/). Both are signed MSI/EXE packages.

### No admin rights on this machine?

Use **Scoop** (above): it installs under `%USERPROFILE%\scoop` and never asks for
elevation. Git for Windows also offers a per-user install, and `winget install Git.Git
--scope user` selects it.

### The bash question (this one surprises people)

Parts of this repository are POSIX shell scripts: the demo chain in
`demo/kup-training/`, and three of the gates in the stage 2 script. **Git for Windows
already ships a bash**, so you do not install anything extra. But its recommended setup
puts only `...\Git\cmd` on your PATH (that is `git.exe`), **not** `...\Git\bin` (that is
`bash.exe`). So `bash` alone will usually fail in PowerShell on a machine that has a
perfectly good bash.

Three ways out, in order of preference:

```powershell
# 1. Call it by path (works everywhere, changes nothing):
& "$env:ProgramFiles\Git\bin\bash.exe" run-all.sh --offline-only --no-pdf --no-release

# 2. Add it to this session only:
$env:Path += ";$env:ProgramFiles\Git\bin"
bash --version

# 3. Use the "Git Bash" entry in the Start menu and run the script there.
```

`scripts\skillctl-enterprise-test.ps1` finds Git's bash by itself, next to wherever
`git.exe` lives, so you do not need any of this for the stage 2 gates.

**A warning about `bash` on PATH.** If `bash` does resolve in PowerShell, it is often
`C:\Windows\System32\bash.exe`, which is **WSL**, not Git. With a Linux distro installed it
answers `--version` happily and then runs the script inside Linux, against `/mnt/c/...`
paths and a different `git`. That is a different machine wearing your machine's name. Use
Git's bash for these scripts.

### Optional, and what you lose without each

| Tool | Install | Without it |
|---|---|---|
| **gcc** (mingw-w64) | `winget install --id MSYS2.MSYS2` then `pacman -S mingw-w64-x86_64-gcc` | The Go race detector needs cgo and a C compiler. The tests still run; the stage 1 report shows `Race SKIP` instead of a pass |
| **jq** | `winget install --id jqlang.jq -e` | The stage 2 `gosec` diff gate reports SKIP |
| **gitleaks** | see the pinned install in `.github/workflows/ci.yml` | The stage 2 `gitleaks` gate reports SKIP. Deliberately not auto-installed: CI verifies its release tarball against a pinned SHA-256 first, and a convenience script must not fake that |

`golangci-lint`, `gosec` and `go-test-coverage` are installed on demand by the stage 2
script, at the versions CI pins, into `(go env GOPATH)\bin`. You do not install them by
hand, and `-NoInstall` forbids it if you would rather not.

### Windows-specific execution policy

The one-liners start with:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

`-Scope Process` applies to that one PowerShell window and dies with it. It changes nothing
for your user or the machine.

---

## macOS

```bash
brew install git go        # git is also in the Xcode command line tools
xcode-select --install     # optional: the C toolchain, which enables the race detector
```

`brew install portaudio pkg-config` only matters if you widen the stage 2 gates to `./...`
with `--full`: the audio packages need it. Without it those gates report SKIP rather than a
misleading red.

## Linux

```bash
sudo apt install git golang-go build-essential   # Debian, Ubuntu
sudo dnf install git golang gcc                   # Fedora, RHEL
```

If your distribution's Go is older than 1.25, take the tarball from
[go.dev/dl](https://go.dev/dl/) instead; a package manager one minor version behind is the
most common cause of a failed first build.

---

## Verify, then start

```
git --version      # any recent version
go version         # must be 1.25.0 or newer
```

Then: [stage 1, the machine check](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test),
[stage 2, the CI gates](quickstart-skillctl.md#1c-stage-2-run-our-ci-on-your-own-machine-enterprise-gate),
[stage 3, the Test Ride](quickstart-skillctl.md#1d-the-human-half-the-test-ride).

Nothing above needs a server, an account or a network connection beyond the installs
themselves. The ride is offline.
