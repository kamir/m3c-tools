Für die Installer brauchen Sie cosign oder ein OpenSSL mit ed25519-Unterstützung. macOS bringt beides nicht mit; führen Sie dort `brew install cosign` aus. Der Bau aus dem Quellcode braucht beides nicht.

---
layout: default
title: Voraussetzungen
---

# Voraussetzungen vor dem ersten Start

[Deutsch](prerequisites.de.md) · [English](prerequisites.md)

Zwei Werkzeuge auf jeder Plattform: **git** und **Go 1.26.10 oder neuer**. Alles andere
ist optional und unten entsprechend gekennzeichnet. Wenn `git --version` und
`go version` antworten, weiter zum [Quickstart: skillctl](quickstart-skillctl.de.md).

---

## Windows (PowerShell)

### Die beiden erforderlichen Werkzeuge

Windows 10 ab 1809 und Windows 11 enthalten `winget`. Je eine Zeile, ohne manuellen Download:

```powershell
winget install --id Git.Git    -e --source winget
winget install --id GoLang.Go  -e --source winget
```

**Danach PATH neu laden.** `winget` schreibt den Maschinen-PATH, die geöffnete
PowerShell-Sitzung behält aber ihre alte Kopie. Bis zum Öffnen eines neuen Fensters
oder folgendem Befehl scheint `git` deshalb zu fehlen:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path','User')
git --version
go version
```

`go version` muss **1.25.0 oder höher** ausgeben; das verlangt `go.mod`.

### Wenn `winget` fehlt

`winget` gehört zum Paket **App Installer**. Dieses aus dem Microsoft Store installieren
oder eine der folgenden Alternativen verwenden:

```powershell
# Scoop: per-user, no admin rights at any point
irm get.scoop.sh | iex
scoop install git go

# Chocolatey: machine-wide, needs an elevated shell
choco install git golang -y
```

Alternativ die Installer von Hand herunterladen:
[git-scm.com/download/win](https://git-scm.com/download/win) und
[go.dev/dl](https://go.dev/dl/). Beide sind signierte MSI-/EXE-Pakete.

### Keine Administratorrechte auf diesem Rechner?

**Scoop** von oben verwenden: Es installiert unter `%USERPROFILE%\scoop` und verlangt
keine erhöhten Rechte. Git for Windows bietet ebenfalls eine Installation pro Nutzer;
`winget install Git.Git --scope user` wählt sie aus.

### Die Frage nach bash

Teile dieses Repositorys sind POSIX-Shellskripte: die Demokette in
`demo/kup-training/` und drei Prüfungen des Stage-2-Skripts. **Git for Windows enthält
bereits eine bash**, eine zusätzliche Installation ist nicht erforderlich.
Die empfohlene Einrichtung nimmt allerdings nur `...\Git\cmd`, also `git.exe`, in PATH
auf, **nicht** `...\Git\bin` mit `bash.exe`. Deshalb scheitert `bash` allein in PowerShell
häufig, obwohl eine funktionsfähige bash vorhanden ist.

Drei Möglichkeiten, in der empfohlenen Reihenfolge:

```powershell
# 1. Call it by path (works everywhere, changes nothing):
& "$env:ProgramFiles\Git\bin\bash.exe" run-all.sh --offline-only --no-pdf --no-release

# 2. Add it to this session only:
$env:Path += ";$env:ProgramFiles\Git\bin"
bash --version

# 3. Use the "Git Bash" entry in the Start menu and run the script there.
```

`scripts\skillctl-enterprise-test.ps1` findet Gits bash selbst neben `git.exe`.
Für die Stage-2-Prüfungen sind diese manuellen Schritte daher nicht nötig.

**Achtung bei `bash` in PATH.** Wenn PowerShell `bash` findet, ist das häufig
`C:\Windows\System32\bash.exe`, also **WSL** statt Git. Mit installierter Linux-Distribution
antwortet es auf `--version`, führt das Skript dann jedoch unter Linux gegen
`/mnt/c/...` und ein anderes `git` aus. Das ist eine andere Umgebung. Für diese
Skripte Gits bash verwenden.

### Optionale Werkzeuge und die Folgen ihres Fehlens

| Werkzeug | Installation | Ohne dieses Werkzeug |
|---|---|---|
| **gcc** (mingw-w64) | `winget install --id MSYS2.MSYS2`, dann `pacman -S mingw-w64-x86_64-gcc` | Der Go-Race-Detector benötigt cgo und einen C-Compiler. Tests laufen trotzdem; Stage 1 meldet `Race SKIP` statt bestanden |
| **jq** | `winget install --id jqlang.jq -e` | Die Stage-2-Differenzprüfung von `gosec` meldet SKIP |
| **gitleaks** | Gepinnte Installation in `.github/workflows/ci.yml` | Die Stage-2-Prüfung `gitleaks` meldet SKIP. Absichtlich keine automatische Installation: CI prüft das Release-Archiv zuerst gegen einen gepinnten SHA-256; ein Komfortskript darf dies nicht vortäuschen |

Das Stage-2-Skript installiert `golangci-lint`, `gosec` und `go-test-coverage` bei
Bedarf in den von CI gepinnten Versionen nach `(go env GOPATH)\bin`.
Eine manuelle Installation ist nicht nötig; `-NoInstall` verbietet sie auf Wunsch.

### Windows-Ausführungsrichtlinie

Die Einzeiler beginnen mit:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
```

`-Scope Process` gilt nur für dieses PowerShell-Fenster und endet mit ihm.
Die Richtlinie Ihres Nutzers oder des Rechners wird nicht verändert.

---

## macOS

```bash
brew install git go        # git is also in the Xcode command line tools
xcode-select --install     # optional: the C toolchain, which enables the race detector
```

`brew install portaudio pkg-config` ist nur nötig, wenn die Stage-2-Prüfungen mit
`--full` auf `./...` erweitert werden: Die Audiopakete benötigen es. Ohne diese
Abhängigkeiten melden die Prüfungen SKIP statt irreführend fehlzuschlagen.

## Linux

```bash
sudo apt install git golang-go build-essential   # Debian, Ubuntu
sudo dnf install git golang gcc                   # Fedora, RHEL
```

Ist das Go-Paket Ihrer Distribution älter als 1.25, das Archiv von
[go.dev/dl](https://go.dev/dl/) verwenden. Eine um eine Nebenversion zurückliegende
Paketverwaltung ist die häufigste Ursache für einen fehlgeschlagenen ersten Build.

---

## Prüfen und starten

```
git --version      # any recent version
go version         # must be 1.25.0 or newer
```

Danach: [Stage 1, Maschinenprüfung](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test),
[Stage 2, CI-Prüfungen](quickstart-skillctl.md#1c-stage-2-run-our-ci-on-your-own-machine-enterprise-gate),
[Stage 3, Test Ride](quickstart-skillctl.md#1d-the-human-half-the-test-ride).

Nichts davon benötigt einen Server, ein Konto oder eine Netzwerkverbindung über
die Installationen selbst hinaus. Der Test Ride funktioniert offline.
