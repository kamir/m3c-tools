# Runbook: the audit trail, three mechanisms, three questions

Sprachen / Languages: [Deutsch](audit-spur.de.md) | [English](audit-spur.en.md)

Reading skillctl's audit trail means dealing with three verbs that sound
similar but answer three different questions. This page brings them together.
Its basis is the three sections of the
[skillctl manual](../referenz/manual-skillctl.md) (`audit`, `auditlog`,
`translog`) and the code (`pkg/skillctl/audit/audit.go`,
`cmd/skillctl/auditlog_cmds.go`, SPEC-0278), read on 2026-09-16.

Audience: Security / CISO and Operations. The
[overview](ueberblick.en.md) introduces the complete security view; the
registry timeline (admit, attest, revoke, install) is in the
[incident runbook, section 1](../betrieb/ops-incident-response.en.md).

Role: Security, Operations · Language: EN · Updated: 2026-09-16

## The core rule in one sentence

**Three mechanisms, three separate exit-code spaces, and none may be read as
another:** `audit` judges installed inventory (posture), `auditlog` judges the
health of the audit subsystem, and `translog` judges the immutability of the
event history. The separation is deliberate: interpreting a health finding
as a posture finding causes a false alarm or false reassurance (manual,
`auditlog` section).

| Mechanism | Question | Exit-code space |
|---|---|---|
| `skillctl audit` | What is on this machine, and is it sound? | `0` everything OK · `2` UNVERIFIED/BELOW_MIN or refusal/usage · `3` BROKEN · `1` internal error |
| `skillctl auditlog` | Is the audit event layer itself functioning? | `0` healthy/accepted/flushed · `1` unhealthy/rejected/error · `2` usage |
| `skillctl translog` | Is the history unchanged and complete? | `verify`: `0`/`23` not-included · `witness`: `0`/`24` split-view · `consistency`: `0`/`25` rewrite · each `1` otherwise, `2` usage |

## Mechanism 1: `skillctl audit`, the verdict per skill

Prints a verdict per skill: `OK | UNVERIFIED | BROKEN | BELOW_MIN`. Only
`0/2/3` are the posture verdict (`exitCodeFor`,
`pkg/skillctl/audit/audit.go`); `1` is the ordinary internal error code.

Cleanup is destructive and follows the G-23 two-step procedure,
without `--force`:

```bash
skillctl audit --cleanup --dry-run-cleanup                               # Schritt 1: Plan + signiertes Token
skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <sig>  # Schritt 2: Re-Check + Loeschen
```

Step 1 deletes nothing and prints a signed token (HMAC over hostname, sorted
affected paths and issue time, valid for 5 minutes). Step 2 computes the
affected set AGAIN and checks the token against it: drift, expiration or
tampering causes refusal with exit `2` and no deletion. A destructive operation
that no longer matches its approved plan simply does not run (manual,
"The G-23 two-step contract").

## Mechanism 2: `skillctl auditlog`, event-layer health

The audit event layer's observability CLI (SPEC-0403 §8), with its own verb
family and exit-code space `0/1` (`2` usage, `auditlogExitUsage` in
`cmd/skillctl/auditlog_cmds.go`):

| Subcommand | Purpose |
|---|---|
| `status` | Health: enabled, mode, sink type and path, outbox and spool backlog, latest event |
| `test` | ONE clearly synthetic `skillctl.audit.v1` event through the real sink, with acceptance confirmed |
| `flush` | Transfer the local spool into the durable outbox; the local half only, no broker egress |

Two limits, both documented and anchored in code: **there is no Kafka**
(a direct broker sink is FR-0112 and EC-blocked; `status` invents no endpoint),
and network egress is exclusively through `skillctl sync` (default-OFF).
A transport error appears as an observable event on stderr and is never
reported through the sink that has just failed (no recursive error loop,
REQ-8.2).

## Mechanism 3: `skillctl translog`, the L1 transparency log

A local RFC-6962 Merkle log (SPEC-0278, stdlib only). L1 makes equivocation
and withholding **detectable**, not impossible. Event data stays out of the
log; only the digest of the already signed event is appended
(`sha256:<64 hex>`, types `admit | attest | revoke | agentid-issue |
agentid-revoke`). Default path:
`~/.claude/skillctl/transparency-log.jsonl`.

The verification chain, with every stage offline:

```bash
skillctl translog append admit sha256:<hex> --subject mein-skill
skillctl translog sth --key <log.priv>                        # Kopf zeigen/signieren
skillctl translog prove sha256:<hex> --key <log.priv> --out receipt.json
skillctl translog verify --receipt receipt.json --log-pubkey log.pub   # 0 ok · 23 not-included
skillctl translog consistency --sth1 a.json --sth2 b.json --proof '[..]'  # 25 = Rewrite erkannt
skillctl translog witness --sths sths.json --log-pubkey log.pub           # 24 = Split-View erkannt
```

`verify` explicitly requires the pinned log public key: an unpinned key
would verify nothing (manual, `translog` section).

## What this page does not claim

The numbers `23/24/25` are the documented finding codes for translog checks;
`cmd/exitaudit` checks the underlying register against
`pkg/skillctl/exitcode` whenever `scripts/check-docs.sh` runs. This page cites
the manual and code; it replaces neither the
[manual](../referenz/manual-skillctl.md) nor the verb register
[CLI-VERBS](../referenz/CLI-VERBS.md).
