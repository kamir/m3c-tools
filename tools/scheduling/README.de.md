# Zeitplanung der skillctl-Widerrufsprüfung (SPEC-0251 §5 / SPEC-0247)

[Deutsch](README.de.md) | [English](README.md)

`skillctl verify --all --quarantine` versucht die konfigurierten Vertrauens- und
Widerrufsprüfungen für den installierten Bestand. Je nach verfügbaren Nachweisen werden
Online-, Offline-, Sidecar- oder Unmanaged-Policy-Pfade genutzt. Der Bericht nennt deren
Prüfumfang; unbestätigte Nachweise verhindern den Gesamterfolg. Abgelehnte verwaltete
Skills können in Quarantäne verschoben werden; der Urteilscache wird aktualisiert.
Ist ein SessionStart-Hook in `~/.claude/settings.json` installiert, kann er diesen Sweep
aufrufen. Die Beispiel-Units ergänzen einen Timer für lange laufende Rechner oder
Systeme ohne grafische Oberfläche, die selten neue Claude-Code-Sitzungen starten.

> **Einschränkung bei Offline-Widerruf:** Ein serverseitiger Widerruf wird erst
> nach der nächsten **Online**-Prüfung durchgesetzt. Der lokale Timer schließt
> dieses Fenster regelmäßig, macht Widerrufe aber nicht augenblicklich wirksam.

Alle Varianten führen denselben Befehl aus und protokollieren JSON unter
`~/.claude/skillctl/`:

```
skillctl verify --all --quarantine --json
```

Die folgenden Beispiele sind **bis zur Installation inaktiv**. Prüfen Sie sie,
passen Sie den absoluten `skillctl`-Pfad an Ihren Rechner an und aktivieren Sie
sie erst danach. Ohne ausdrückliche Installation geschieht nichts automatisch.

Der Sweep liefert jetzt `1` bei ungültigen, unvollständig geprüften oder übersprungenen
Skills, auch nach erfolgreicher Quarantäne; `0` bedeutet vollständigen Erfolg oder
explizit leeren Bestand, `2` ungültige Argumente. Im versionierten JSON `ok`, `complete`
und Einträge überwachen. `quarantined` zählt tatsächliche Verschiebungen;
`quarantine_candidates` schließt nur gemeldete und fehlgeschlagene Versuche ein.
Offline-Prüfungen können den Widerrufsstand unbestätigt lassen. Timer und Hooks müssen
Fehlerstatus erhalten und melden, statt ihn als erfolgreiche Verifikation zu interpretieren.

---

## macOS: launchd (LaunchAgent je Nutzer)

```sh
# 1. Edit guide.m3c.skillctl-sweep.plist: set the absolute path to skillctl.
# 2. Install + load:
cp tools/scheduling/guide.m3c.skillctl-sweep.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
# Runs daily + once at load. Disable: launchctl unload -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
```

## Linux: systemd-Timer je Nutzer

```sh
# Edit skillctl-sweep.service: set the absolute ExecStart path to skillctl.
mkdir -p ~/.config/systemd/user
cp tools/scheduling/skillctl-sweep.service tools/scheduling/skillctl-sweep.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now skillctl-sweep.timer
# OnCalendar=daily, Persistent=true (runs on next boot if a run was missed).
# Status: systemctl --user list-timers skillctl-sweep.timer
```

### Ausweichlösung cron (jedes POSIX-System)

```cron
# ~/crontab: daily at 09:00; adjust the skillctl path.
0 9 * * *  $HOME/.local/bin/skillctl verify --all --quarantine --json >> $HOME/.claude/skillctl/sweep.log 2>&1
```

## Windows: Aufgabenplanung

```powershell
# Edit the path to skillctl.exe, then register a daily task:
schtasks /create /tn "skillctl-sweep" /sc DAILY /st 09:00 ^
  /tr "C:\Users\%USERNAME%\.local\bin\skillctl.exe verify --all --quarantine --json"
# Remove: schtasks /delete /tn "skillctl-sweep" /f
```
