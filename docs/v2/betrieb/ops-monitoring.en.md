# Operations runbook: monitoring and alerting

Sprachen / Languages: [Deutsch](ops-monitoring.de.md) | [English](ops-monitoring.en.md)

What can currently be observed in a skillctl deployment, where monitoring
can connect, and what the available tools **cannot** do.

Audience: the fleet operator and the person setting up its monitoring.

**How much of this runbook has been measured.** Blocks introduced as
"Measured" were run on 2026-09-07: against the binary, against the source
tree, and, for audit-log counts, against an established workstation.
Absolute line counts belong to that particular machine and continue changing;
the finding is always the relationship between counts. Adjacent commands
provide the self-test for your machine. Shortening uses `/…/` for paths
and `[…]` for output.

## The honest assessment first

**There is no metrics surface.** No `/metrics`, Prometheus exporter,
OpenTelemetry or statsd. Measured on 2026-09-07 across the entire tree:

```
$ grep -rn "prometheus\|/metrics\|statsd\|opentelemetry\|otel" --include="*.go" pkg/skillctl cmd/skillctl
pkg/skillctl/auditevent/event_test.go:28:  if err := e.SetExt("trace_id", "otel-abc"); err != nil {
```

One match, and that is a test value. Nothing exposes counters; nothing
reports to a target system on its own.

**What exists instead: commands to query.** Everything below is pull-based:
one invocation, an exit code, optionally JSON on stdout. Build monitoring
on top as a scheduled task rather than a subscription.

This is deliberate architecture: the gate decision must not depend on
whether observation succeeds. Logging is therefore intentionally separate
from the decision path, and the same separation limits reporting channels.

## 1. The four commands supporting monitoring

### `skillctl auditlog status`

Reports whether the audit subsystem can still write at all.

```
$ skillctl auditlog status
skillctl auditlog status
  Audit:        ENABLED
  Mode:         best-effort (gate default, decision-invariant; durable outbox available)
  Sink:         file
  Sink path:    /…/.claude/skillctl/gate-audit.jsonl
  Outbox:       0 pending (awaiting `skillctl sync` egress, default-OFF)
  Spool:        0 pending (un-reconciled; drain with `skillctl auditlog flush`)
  Last event:   (none recorded)
  Health:       HEALTHY
$ echo $?
0
```

Machine-readable:

```
$ skillctl auditlog status --json
{
  "enabled": true,
  "mode": "best-effort (gate default, decision-invariant; durable outbox available)",
  "sink": "file",
  "sink_path": "/…/.claude/skillctl/gate-audit.jsonl",
  "outbox_pending": 0,
  "spool_pending": 0,
  "healthy": true
}
```

| Exit | Meaning |
|---|---|
| 0 | Healthy: the audit directory is writable |
| 1 | Unhealthy |
| 2 | Invocation or flag error |

Here the exit code is a real alarm signal because it is tied to a probe
(whether the directory is writable), not an opinion.

**The two numbers to monitor.** `spool_pending` should drop to 0 after
`skillctl auditlog flush`; if it does not, the hot path is not reaching
the durable outbox. `outbox_pending` grows while no `skillctl sync` runs,
which is the **normal case**: export is off by default. A threshold on
`outbox_pending` therefore makes sense only if `sync` is actually configured.

### `skillctl gate-stats`

Summarizes the gate's decisions.

```
$ skillctl gate-stats --since 168h
gate-audit summary, 0 event(s) since 168h
  (no events, the gate hasn't logged anything in this window)
$ echo $?
0
```

`--json` returns the same summary in machine-readable form, with fields
`total`, `since`, `by_decision`, `by_source`, `hook_count`,
`hook_cache_hit_rate`, `top_denied_skills`, `top_deny_reasons` and
`recent_denials`.

**The exit code is not an alarm signal here.** `gate-stats` returns 0
whether it found 0 or 10000 blocks. To alert, evaluate `by_decision` from
the JSON. Also, `gate-stats` reads **only this machine's local file**;
a fleet-level statement requires collection.

### `skillctl doctor`

A machine's condition: pins, keys, directories.

```
$ skillctl doctor
skillctl doctor
--------------------------------------------------------------
ok    version      skillctl dev (darwin/arm64, go1.26.6)
ok    home         /…  ($HOME)
todo  skills dir   /…/.claude/skills does not exist yet
                   -> it is created by the first `skillctl install`
todo  trust roots  /…/.claude/skill-trust-roots.yaml not present
…
--------------------------------------------------------------
USABLE, 4 step(s) not done yet. Nothing here is broken.
$ echo $?
0
```

**Beware: the exit code misleads.** `doctor` returns 1 when something is
**present and unusable** ("NOT READY"), and 0 both for "READY" and for
"USABLE, n step(s) not done yet". A machine with no trust roots therefore
returns exit 0. To monitor that distinction, check the final line for
`READY:`, not the exit code. This is the only place in this runbook where
the obvious method measures the wrong thing.

### `skillctl pin status`

Whether the gate is pinned against removal or merely advisory.

```
$ skillctl pin status
managed settings: /Library/Application Support/ClaudeCode/managed-settings.json
gate pinning:     absent
  SessionStart sweep hook: no
  PreToolUse verify-hook:  no
  - no managed-settings file at …: the gate is ADVISORY (a user can delete the user-level hook). Run `skillctl pin install`.
$ echo $?
2
```

| Exit | Meaning |
|---|---|
| 0 | Pinned |
| 1 | Read error |
| 2 | **Not** pinned |

Here the exit code is the alarm source, with 2 the interesting value.
This is unusual because 2 elsewhere in the tool means "usage error";
for this verb it means "not pinned".

## 2. Two more integration points

### `skillctl verify --all --json`

A report on a machine's skill inventory:

```json
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  "verified": 0,
  "quarantined": 0,
  "unverified": 0,
  "skipped": 0,
  "entries": null
}
```

Monitor `quarantined > 0` (something failed) and `unverified > 0` (the run
did not finish within its time budget, so nothing is known about these
skills). `unverified` is the quieter and therefore more important number.

**Redirecting to `> bericht.json` does not produce valid JSON.** If there
is nothing to check, the command writes a plaintext line **to stdout**
before the JSON. Measured with stderr suppressed:

```
$ skillctl verify --all --json 2>/dev/null
skillctl verify --all: no installed skills at /…/.claude/skills (nothing to sweep)
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  …
}
```

A consumer therefore starts at the first `{` line, for example using
`sed -n '/^{/,$p'`. `gate-stats --json` and `auditlog status --json` do not
have this behavior; both write only the document.

### `skillctl revoke feed`

Whether the machine has a fresh signed revocation HEAD:

```bash
skillctl revoke feed --registry https://<host>/api/skills
```

Checks the HEAD signature against the **pinned** registry key and reports
epoch, issue time and staleness. `--refresh` fetches it. Without this call,
the local view ages, which is exactly what monitoring should detect here.

**`--status` now exists; the previously documented parser error is fixed.**
An older version of this block (measured on 2026-09-07) showed
`flag provided but not defined: -status` with exit 2; since commit
`b9a79d2`, the flag is defined (`cmd/skillctl/revoke_feed_cmds.go:35`, as
"(default)"). Measured on 2026-09-16, binary from this tree
(`skillctl/v0.5.1-6-g307b414`), against a nonexistent name:

```
$ skillctl revoke feed --status --registry https://<unerreichbar>/api/skills
skillctl revoke feed: fetch failed: Get "https://<unerreichbar>/api/skills/revocations/head": dial tcp: lookup <unerreichbar>: no such host
$ echo $?
1
```

The flag is accepted; execution reaches fetch and behaves like invocation
without the flag: status retrieval is the default. A scheduled task may
therefore explicitly specify `--status`; a binary predating `b9a79d2`
still produces the old exit 2, in which case the behavior of that binary
applies, not this runbook.

**The status retrieval exit code is useful; `--refresh` depends on whether
the machine is managed.** Managed here means that the flat
`~/.claude/trust-roots.yaml` exists. Measured against a nonexistent name:

| Invocation | Machine | Output | Exit |
|---|---|---|---|
| `revoke feed --registry https://<unerreichbar>/api/skills` | Both | `fetch failed: … no such host` | 1 |
| `revoke feed --refresh --registry https://<unerreichbar>/api/skills` | Without flat `trust-roots.yaml` | `refreshed: 0 revoked digest(s), epoch=0 issued_at="" online=false` | 0 |
| `revoke feed --refresh --registry https://<unerreichbar>/api/skills` | With flat `trust-roots.yaml` | Same line, plus `revocation unavailable under managed trust roots (fail-closed, exit 22)` | 22 |

On an unmanaged machine, a refresh that reached nothing reports success;
the actual information is in `online=false`. On a managed machine, the
tool fails closed once no fresh cache limits staleness; during that grace
window it still returns exit 0 with `online=false`.

A rule that works on both: **alert on `online=false`**, and treat exit 22
as a finding, not a bad invocation. Reading only the exit code reveals
nothing on the unmanaged machine.

## 3. The underlying files

| File | Contents |
|---|---|
| `~/.claude/skillctl/gate-audit.jsonl` | One line per gate decision, in **two** formats, see below |
| `~/.claude/skillctl/gate-audit.jsonl.1` | The single rotated generation |
| The SPEC-0317 outbox | Durable evidence rows available for export |

**Two line formats coexist in the same file.** The current binary writes
only the envelope with `"schema":"skillctl.audit.v1"`; the old flat rows
from before the FR-0110a change remain in the same file and are not migrated.
Measured on 2026-09-07 on an established workstation; absolute counts belong
to that file and change with every gate invocation, while their relationship
is the finding:

```
$ wc -l < ~/.claude/skillctl/gate-audit.jsonl
6375
$ grep -c '"schema"' ~/.claude/skillctl/gate-audit.jsonl
2327
$ grep -vc '"schema"' ~/.claude/skillctl/gate-audit.jsonl
4048
```

These three lines are the self-test: run them on your own machine to
measure the gap there. If the third number is greater than zero, both
formats are present.

The two formats, verbatim from the same file, deliberately showing the
same decision twice so that only the format differs:

```
{"ts":"2026-09-04T06:54:24Z","source":"hook","skill":"s","decision":"deny","reason":"freshness:stale_high_risk_fail_closed","exit_code":22,"content_digest":"s","online":false,"cache_hit":false}

{"actor":{"type":"gate","id":"hook"},"event_id":"01M1XNP6DSCHEBDFFY6W7GRB9W","event_type":"policy.deny","gate.cache_hit":false,"gate.exit_code":22,"gate.online":false,"message":"freshness:stale_high_risk_fail_closed","outcome":"deny","policy":{"decision":"deny"},"producer":"dev","schema":"skillctl.audit.v1","severity":"warning","skill":{"name":"s","digest":"s"},"timestamp":"2026-09-07T10:12:43Z"}
```

The flat row's `decision` becomes `policy.decision` in the envelope;
`reason` becomes `message`, `exit_code` becomes `gate.exit_code`, and
`skill` changes from a string to an object. A consumer knowing only the
flat field names finds nothing in the envelope.

This has two consequences for log shipping:

* **A filter on `schema` silently loses old rows.** In the measured log,
  that means 4048 of 6375 rows. They have no `schema` field, so every rule
  depending on it drops them without an obvious sign of missing data.
  If filtering is necessary, match `decision` **or** `policy.decision`
  and retain both formats.
* **`gate-stats` has the same gap, deliberately.** It reads only rows with
  `schema: skillctl.audit.v1` **and** a `policy.decision`; everything else
  is skipped. Measured on the same file:

```
$ skillctl gate-stats --since 100000h --json | head -3
{
  "total": 2326,
  "since": "100000h",
```

  2326 instead of 6375; the difference of one from the 2327 envelope rows
  is an envelope without a policy block. This too is measured, not inferred:
  it is the synthetic event from `skillctl auditlog test`, identifying
  itself as `"synthetic":true` and "NOT a real audit record". A
  `gate-stats` statement about a period before the change is therefore
  not a statement about that period's gate decisions.

Apart from that, it is a **structured line file**, so log shipping can
connect to it. Two further limitations, both established in code:

1. **Rotation with exactly one generation.** At 5 MiB, the file rotates to
   `.jsonl.1`; the previous `.1` disappears. Log shipping slower than the
   incoming volume loses rows from disk. Durable evidence is the outbox,
   not this file.
2. **The file is telemetry, not a trust input.** Corrupted rows are skipped,
   not reported. A plausible `gate-audit.jsonl` says nothing about completeness.

Export, if configured:

```bash
skillctl sync --once --endpoint https://<ingest>/… --ingest-pubkey <pem>
skillctl sync --daemon --interval 1m --endpoint https://<ingest>/… --ingest-pubkey <pem>
```

Export is **off by default** ("Default OFF, local-only evidence").
Without `--endpoint` and `--ingest-pubkey`, no rows are marked as exported.

`skillctl auditlog flush` additionally writes an observation event to
stderr, on a **different** channel from the sink it reports on:

```
{"event_id":"01M1XM…","event_type":"audit.queue.flush","message":"reconciled 0 spooled row(s) into the durable outbox","observability":true,"outcome":"success","producer":"skillctl/dev","schema":"skillctl.audit.v1","severity":"info","timestamp":"2026-09-07T09:48:06.147Z"}
```

## 4. The token register is part of monitoring

Token expiration dates are **not stored in tokens**, and `skillctl` does
not know them. `skillctl token list --host <host>` shows stored entries,
printing neither a token nor a date:

```
$ skillctl token list --host git.example.com
credentials for git.example.com
  protected store: macOS Keychain

  gitlab    read   not provisioned              env: M3C_GITLAB_RO_TOKEN
  gitlab    write  not provisioned              env: M3C_GITLAB_TOKEN
  …
```

The only place containing an expiration date is the register in
[part C of the token routine](ops-registry-tokens.de.md#teil-c-das-token-register).
Monitoring expiration dates currently means a calendar reminder based on
the "Expires" column, not something a tool can generate.

## 5. Minimal monitoring that works today

One scheduled task per machine (launchd, Task Scheduler, cron), daily,
writing to a file collected by existing log shipping:

```bash
#!/usr/bin/env bash
# skillctl-health.sh: pull-basierte Zustandsprobe, ein Aufruf je Signal.
# Kein Alarm hier drin: die Datei ist das Signal, das Auswerten macht das
# vorhandene Log- oder Monitoring-Werkzeug.
set -u
out=${1:-/var/log/skillctl-health.json}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# JSON erst ab der ersten offenen Klammer: `verify --all --json` stellt bei
# einem leeren Lauf eine Klartextzeile auf stdout davor.
only_json() { sed -n '/^{/,$p' "$1"; }

skillctl auditlog status --json > "$tmp/auditlog.json" 2>/dev/null
auditlog_exit=$?

skillctl pin status > /dev/null 2>&1
pin_exit=$?

skillctl gate-stats --since 24h --json > "$tmp/gate-stats.json" 2>/dev/null
skillctl verify --all --json      > "$tmp/verify-all.json" 2>/dev/null

skillctl doctor > "$tmp/doctor.txt" 2>&1
doctor_ready=$(grep -c '^READY:' "$tmp/doctor.txt" || true)

cat > "$out" <<JSON
{
  "ts": "$(date -u +%FT%TZ)",
  "host": "$(hostname)",
  "auditlog_exit": $auditlog_exit,
  "pin_status_exit": $pin_exit,
  "doctor_ready": $doctor_ready,
  "auditlog": $(only_json "$tmp/auditlog.json"),
  "gate_stats": $(only_json "$tmp/gate-stats.json"),
  "verify_all": $(only_json "$tmp/verify-all.json")
}
JSON
```

Exit codes are captured **immediately** after their commands. Reading them
only in the output statement reads the exit code of that output statement.

The script ran on 2026-09-07 against a fresh `$HOME` and wrote valid JSON:
`auditlog_exit=0`, `pin_status_exit=2`, `doctor_ready=0`,
`verify_all.total=0`.

The four useful alarms derived from this:

| Alarm | Condition | Reason |
|---|---|---|
| Audit unavailable | `auditlog_exit != 0` | Evidence stops being generated from this point |
| Gate not pinned | `pin_status_exit == 2` | The gate is only advisory |
| Skill failed | `verify_all.quarantined > 0` | Something installed does not pass the chain |
| Blind spot | `verify_all.unverified > 0` | The run did not finish; nothing is known |

A fifth once `sync` is configured: `auditlog.outbox_pending` increases
monotonically across several runs, indicating export is not getting through.

## 6. What this explicitly cannot do

**No metrics.** No `/metrics`, exporter, counters or histograms. Build a
dashboard on the JSON outputs above if needed; resolution is the interval
between scheduled runs, not the event time.

**No alerting.** Nothing sends. Alerts exist only where someone evaluates
the exit codes and JSON fields above.

**No fleet view.** Every command describes **this** machine. There is no
query for "which machines are outdated". Collection belongs to the existing
logging or configuration tool.

**No event stream.** A broker sink is not built (FR-0112, blocked);
`auditlog status` therefore deliberately invents neither endpoint nor topic.
What exists is the file and export through `skillctl sync`.

**No completeness guarantee on disk.** See rotation in section 3.
Durable evidence is the outbox.

**No token-expiration warning.** See section 4.

**No alarm on an arriving revocation.** The revocation HEAD is fetched,
not delivered. Without a scheduled `revoke feed --refresh`, a machine
notices nothing; see [Incident Response](ops-incident-response.en.md).

## Related runbooks

| Runbook | Purpose |
|---|---|
| [Operations routine: access tokens](ops-registry-tokens.en.md) | The token register with expiration dates |
| [Incident Response](ops-incident-response.en.md) | What to do when an alarm is real |
| [Registry backup and restore](ops-registry-backup-restore.en.md) | Nobody automatically checks that the backup runs |
