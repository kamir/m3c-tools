# Scheduling the skillctl revocation sweep (SPEC-0251 §5 / SPEC-0247)

[Deutsch](README.de.md) | [English](README.md)

`skillctl verify --all --quarantine` attempts the configured trust and revocation
checks for the installed inventory. Depending on available evidence, entries use
online, offline, sidecar or unmanaged-policy paths. The report identifies their scope;
unconfirmed evidence prevents overall success. The command can move rejected managed
skills into quarantine and updates the verdict cache. If a SessionStart hook is installed
in `~/.claude/settings.json`, it can run this sweep. These sample units add a timer for
long-lived or headless machines that rarely start a fresh Claude Code session.

> **Caveat (offline-revocation):** a revocation posted server-side is only
> enforced after the next **online** sweep/verify. The local timer closes that
> window on a schedule; it does not make revocation instantaneous.

All recipes run the same command and log JSON to `~/.claude/skillctl/`:

```
skillctl verify --all --quarantine --json
```

The sample files below are **inert until you install them**: review, edit the
absolute `skillctl` path for your machine, then enable. Fail-closed: nothing
auto-installs.

The sweep now returns `1` for invalid, incomplete or skipped skills, even after a
successful quarantine move; `0` means complete success or an explicitly empty inventory,
and `2` means invalid arguments. Monitor the versioned JSON `ok`, `complete` and entries.
`quarantined` counts actual moves, while `quarantine_candidates` also includes report-only
and failed attempts. Offline checks may leave revocation unconfirmed. Timers and hooks
must preserve and report nonzero outcomes rather than interpret them as successful verification.

---

## macOS: launchd (per-user LaunchAgent)

```sh
# 1. Edit guide.m3c.skillctl-sweep.plist: set the absolute path to skillctl.
# 2. Install + load:
cp tools/scheduling/guide.m3c.skillctl-sweep.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
# Runs daily + once at load. Disable: launchctl unload -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
```

## Linux: systemd timer (per-user)

```sh
# Edit skillctl-sweep.service: set the absolute ExecStart path to skillctl.
mkdir -p ~/.config/systemd/user
cp tools/scheduling/skillctl-sweep.service tools/scheduling/skillctl-sweep.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now skillctl-sweep.timer
# OnCalendar=daily, Persistent=true (runs on next boot if a run was missed).
# Status: systemctl --user list-timers skillctl-sweep.timer
```

### cron fallback (any POSIX)

```cron
# ~/crontab: daily at 09:00; adjust the skillctl path.
0 9 * * *  $HOME/.local/bin/skillctl verify --all --quarantine --json >> $HOME/.claude/skillctl/sweep.log 2>&1
```

## Windows: Task Scheduler

```powershell
# Edit the path to skillctl.exe, then register a daily task:
schtasks /create /tn "skillctl-sweep" /sc DAILY /st 09:00 ^
  /tr "C:\Users\%USERNAME%\.local\bin\skillctl.exe verify --all --quarantine --json"
# Remove: schtasks /delete /tn "skillctl-sweep" /f
```
