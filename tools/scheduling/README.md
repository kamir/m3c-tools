# Scheduling the skillctl revocation sweep (SPEC-0251 §5 / SPEC-0247)

`skillctl verify --all --quarantine` re-verifies every installed skill against
the SPEC-0188 §7 trust chain **online** (so it catches server-side revocations)
and moves any trust-failing managed skill out of `~/.claude/skills/` into the
quarantine dir, refreshing the verdict cache. It already runs at **SessionStart**
(the hook in `~/.claude/settings.json`). These sample units run it **on a timer**
too, so long-lived / headless machines that rarely start a fresh Claude Code
session still pick up revocations.

> **Caveat (offline-revocation):** a revocation posted server-side is only
> enforced after the next **online** sweep/verify. The local timer closes that
> window on a schedule; it does not make revocation instantaneous.

All recipes run the same command and log JSON to `~/.claude/skillctl/`:

```
skillctl verify --all --quarantine --json
```

The sample files below are **inert until you install them** — review, edit the
absolute `skillctl` path for your machine, then enable. Fail-closed: nothing
auto-installs.

---

## macOS — launchd (per-user LaunchAgent)

```sh
# 1. Edit guide.m3c.skillctl-sweep.plist: set the absolute path to skillctl.
# 2. Install + load:
cp tools/scheduling/guide.m3c.skillctl-sweep.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
# Runs daily + once at load. Disable: launchctl unload -w ~/Library/LaunchAgents/guide.m3c.skillctl-sweep.plist
```

## Linux — systemd timer (per-user)

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
# ~/crontab — daily at 09:00; adjust the skillctl path.
0 9 * * *  $HOME/.local/bin/skillctl verify --all --quarantine --json >> $HOME/.claude/skillctl/sweep.log 2>&1
```

## Windows — Task Scheduler

```powershell
# Edit the path to skillctl.exe, then register a daily task:
schtasks /create /tn "skillctl-sweep" /sc DAILY /st 09:00 ^
  /tr "C:\Users\%USERNAME%\.local\bin\skillctl.exe verify --all --quarantine --json"
# Remove: schtasks /delete /tn "skillctl-sweep" /f
```
