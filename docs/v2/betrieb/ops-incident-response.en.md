# Operations runbook: compromised key, compromised registry

Sprachen / Languages: [Deutsch](ops-incident-response.de.md) | [English](ops-incident-response.en.md)

What to do when an author key, a registry key or the registry itself falls
into someone else's hands.

Audience: the registry operator and the person whose key is affected.
If you only operate a machine, read section 5.

**How much of this runbook has been measured.** Every block introduced as
"Measured" was run on 2026-09-07 against the binary, a throwaway `local://`
registry and a throwaway `$HOME`. Paths (`/…/`), digests and fingerprints
(trailing `…`) are shortened; any further output omissions are marked by
an `[…]` line. HTTP registry commands (`https://…/api/skills`) were measured
only as far as execution without a reachable server permits, namely
argument, file and name validation; no instance was available. This limit
is repeated at the affected places. A commitment at the top of a document
is a claim like any other: what is described here is the verified scope,
nothing more.

The companion document [Operations routine: access tokens](ops-registry-tokens.en.md)
covers **tokens**. This runbook covers **keys**. The distinction is central:

> **The token determines who may move the bytes. The key determines to whom
> they are attributed.**

A stolen token allows writes under someone else's identity until GitLab
revokes it. A stolen **key** allows creation of bundles that every machine
in the fleet accepts as genuine, and revoking the token changes nothing
about that. This is why the two procedures are separate.

## 0. The three cases in one sentence

| Case | Attacker capability | What stops it |
|---|---|---|
| **Author key** (`author.key`, `*.priv`) | Sign bundles attributed to this author | Revoke affected digests, then replace the key and repin at every consumer |
| **Registry key** (the key pinned by `trust-roots`) | Forge admit, attest and revoke events; revocation can therefore be suppressed | Overlap window with a new key, then remove the old pin |
| **Registry itself** (project, token, server) | Replace content, delete events | Rebuild from backup, then establish integrity through signatures |

The middle row is the worst. A compromised registry key can conceal a
revocation, so revoking the author key alone is insufficient: the registry
key must rotate too.

## 1. Detect

First establish what is actually in the registry. All three commands are
read-only; none changes anything.

```bash
# Was ist admittiert, was ist schon widerrufen?
skillctl registry ls --registry <locator>

# Die volle Zeitleiste eines Bundles: admit, attest, revoke, install
skillctl registry show <name> --registry <locator>
```

Measured complete `registry show` output after revocation, shortened only
in the path and digest:

```
skill:           demo-skill
registry:        local:///…/probe/skills.git
latest digest:   ?
latest gov:      green
status:          REVOKED

events (newest first):
--------------------------------------------------------------------------------
  2026-09-07T20:48:35Z  revoked    sha256:22a21798c283…
    rationale:  Autorenschluessel kompromittiert, Probe
  2026-09-07T20:48:13Z  attested   sha256:22a21798c283…
    governance: green
    rationale:  Probe
  2026-09-07T20:48:07Z  admitted   sha256:22a21798c283…
```

Two lines of this header are misleading, both measured as shown:

* **`latest digest:   ?`** does not mean "digest unknown"; it means "no
  non-revoked version remains". Name resolution skips revoked versions
  and therefore finds nothing; for the same reason the entire
  `latest version:` line disappears. Before revocation it showed
  `latest version:  1.0.0` with the full digest.
* **`latest gov:      green`** is the earlier attestation. The header
  filters events to the resolved digest; with no digest resolved, the
  filter disappears and the latest `attested` wins, regardless of version.
  With no attestation at all, the line contains a colon placeholder,
  measured on a second throwaway registry with admission and revocation
  but no verdict:

```
latest digest:   ?
latest gov:      :
status:          REVOKED
```

The placeholder is literally a colon and a space; a machine reader must
check exactly that value, not an empty string.

The authoritative information is `status:` and the following event list,
not the header.

On the affected machine, also inspect the local side:

```bash
skillctl gate-stats --since 168h     # was hat das Tor in der letzten Woche geblockt
skillctl auditlog status             # schreibt das Audit-Subsystem überhaupt noch
skillctl doctor                      # Pinnungen, Schlüssel, Verzeichnisse
```

**What is NOT possible here.** There is no query for "which machine has
this bundle installed". `emit-installed` writes a `BundleInstalledEvent`
only if the consumer explicitly requested it during pull. Incident scope
is therefore a question for the token register and the people involved,
not the tool.

## 2. Revoke

**Revoke first, then rotate.** A revocation postponed until after key
replacement needs the old key that has just been deleted.

### Git-backed registry (`local://`, `gitlab://`, `github://`)

```bash
skillctl publish <name> --revoke \
  --digest sha256:<hex> \
  --reason key_compromise \
  --rationale "Autorenschlüssel am <datum> kompromittiert" \
  --version <v> \
  --registry <locator> \
  --key <schlüssel>.priv \
  --identity id:<du>@m3c \
  --yes
```

Measured output:

```
==> publish --revoke demo-skill@1.0.0
    digest:    sha256:5b998c48a366…
    reason:    key_compromise
    rationale: Autorenschluessel kompromittiert, Probe
==> revoked: demo-skill/v1.0.0  transport=git  registry=local:///…/skills.git
```

Afterward, `registry ls` shows `REVOKED` in the `status` column.

### HTTP registry (`https://…/api/skills`)

A separate verb with its own role model:

```bash
skillctl revoke sha256:<hex> \
  --reason key_compromise \
  --role original_author \
  --registry https://<host>/api/skills
```

| Role | Who | Required |
|---|---|---|
| `original_author` (default) | The author | Own key, default `~/.claude/skillctl-keys/author.key` |
| `governance_reviewer` | The approver | `--actor-identity` and `--key` |
| `registry_operator` | The operator | Unsigned; the registry side authenticates over HTTP |

### The `--reason` trap

The two paths validate the reason **differently**. `skillctl revoke`
enforces a closed vocabulary:

```
$ skillctl revoke sha256:… --reason kaputt --registry https://…/api/skills
skillctl revoke: invalid --reason "kaputt" (want one of: key_compromise|vulnerability|governance_retraction|author_request|duplicate)
```

By contrast, `publish --revoke` accepts any string; a revocation with
`--reason kaputt` was measured to pass without warning. To later determine
which revocations involved compromise, manually use `key_compromise`
on the git path as well, and nothing else.

## 3. Rotate

Never switch abruptly when an overlap window is possible. The reasoning
is in the [manual, "Rotate the registry key"](../referenz/manual-skillctl.md#rotate-the-registry-key-overlap-publish-window);
this section gives the incident procedure, which depends on the backend.

It depends on the backend because trust roots live in **three different
files**. This is the most frequent mistake in this runbook, so start with
the table:

| Registry | Pin location | Set using |
|---|---|---|
| `https://…/api/skills` | `~/.claude/skill-trust-roots.yaml` | `skillctl trust add`, `trust remove` |
| `local://`, `gitlab://`, `github://` | `~/.claude/skill-peers.yaml` | `skillctl peer add`, `peer rm` |
| Same backends, without a peer pin | Flat `~/.claude/trust-roots.yaml` | Written manually |
| `self` (ER1) | Flat `~/.claude/trust-roots.yaml` | Written manually |

The flat `~/.claude/trust-roots.yaml` in rows 3 and 4 has a second, less
obvious effect: its mere **presence** makes the machine *managed*, which
determines whether revocation synchronization fails closed or silently
permits access. Measurements appear in section 5.

`trust add` accepts **only** `https://`, plus `http://` for loopback and
RFC1918. Measured:

```
$ skillctl trust add --registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey reg-v2.pub --id kup-v2
trust-roots: registry_url "gitlab://<host>/<gruppe>/skill-registry" must use https:// (or http:// for loopback / RFC1918 only)
$ echo $?
1
```

`local://` and `github://` fail with the same line, as measured. For a
git-backed registry, which is precisely what KuP setup uses, `trust add`
is therefore not an option.

The strict separation of these files is demonstrated by `trust list` in a
`$HOME` containing **only** the flat `trust-roots.yaml`. Measured:

```
$ ls ~/.claude/
trust-roots.yaml
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml (does not exist yet)
no trust roots configured
configure one with: skillctl trust add --registry <url> --pubkey <path>
$ echo $?
0
```

A valid, used trust root exists in the directory, yet `trust list` says
"no trust roots configured" and points to a different file. Checking a
machine's state with `trust list` checks the wrong thing for the git path.

### Git-backed registry (`local://`, `gitlab://`, `github://`)

```bash
# 1) neues Schlüsselpaar beim Betreiber
skillctl keygen --out ~/.config/m3c/skill-registry-v2

# 2) im Fenster jedes noch gültige Bundle unter dem NEUEN Schlüssel neu
#    aufnehmen und neu attestieren
skillctl publish <name>@<v> --bundle <name>@<v>.skb --version <v> \
  --registry gitlab://<host>/<gruppe>/skill-registry \
  --key ~/.config/m3c/skill-registry-v2.priv \
  --identity id:<betrieb>@<org> --yes

# 3) jede Maschine zieht das Pin nach: Abschnitt 4
```

**There is no overlap window for the registry key here.** A locator carries
exactly one pin. Measured:

```
$ skillctl peer add kup-registry-v2 gitlab://<host>/<gruppe>/skill-registry \
    --pubkey <neu-b64> --pin sha256:<neu>
peer add: peers: locator "gitlab://<host>/<gruppe>/skill-registry" is already pinned
$ echo $?
1
```

Reusing the same name is also refused, with a different line. Measured
so the two failures are not confused:

```
$ skillctl peer add kup-registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey <b64> --pin sha256:<hex>
peer add: peers: a peer named "kup-registry" already exists
$ echo $?
1
```

The procedure is therefore `peer rm <name>`, then `peer add` with the new
key. Overlap on this path means briefly running two registries side by
side, or a tightly scheduled switch with the new fingerprint delivered
**beforehand** over the second channel.

**There is a window for the reviewer key.** `--signer` can be repeated,
and quorum remains 1 unless someone increases it. Measured:

```
$ skillctl peer add probe local:///…/probe/skills.git \
    --pubkey <reg-b64> --pin sha256:3b2dc6afd3fa… \
    --signer id:reviewer@probe:<alt-b64> --signer id:reviewer-v2@probe:<neu-b64>
pinned peer "probe" → local:///…/probe/skills.git
  fingerprint: sha256:3b2dc6afd3fa… (matched)
  signer:      id:reviewer@probe
  signer:      id:reviewer-v2@probe
  quorum:      1 of 2 pinned signer(s)
  pull with:   skillctl pull --registry local:///…/probe/skills.git
$ echo $?
0
```

During this window, attestations by either reviewer key count; afterward,
remove the old key from the invocation.

### HTTP registry (`https://…/api/skills`)

Here a registry row can carry multiple keys, providing an overlap window:

```bash
# 1) neues Schlüsselpaar
skillctl keygen --out ~/.config/m3c/skill-registry-v2

# 2) das neue Pin ZUSÄTZLICH setzen, das alte bleibt vorerst stehen
skillctl trust add --registry https://<host>/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id <registry>-v2

# 3) im Fenster alle noch gültigen Bundles unter dem neuen Schlüssel neu admittieren

# 4) nach dem Umstieg: Eintrag entfernen und NUR das neue Pin wieder setzen
skillctl trust remove --registry https://<host>/api/skills
skillctl trust add --registry https://<host>/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id <registry>-v2
```

**Step 4 is not a typo.** `trust remove` removes the entire registry entry
with all its keys; its help says so ("Remove a pinned registry (including
all its keys)"). An individual pin cannot be removed; the old pin
is removed only by rebuilding the entry. Measured with two keys pinned,
then removed and added again:

```
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml

registry: https://beispiel.invalid/api/skills
  identity_keys_authorized: from-registry
  governance_minimum:       green
  registry_keys:
    - id: reg-v1   issued: 2026-09-07
      pubkey (b64): jUndusQ7uIdfHjFbhY3pNMc8Y/oMDoMjDZyGXo94dWg=
    - id: reg-v2   issued: 2026-09-07
      pubkey (b64): LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=

$ skillctl trust remove --registry https://beispiel.invalid/api/skills
removed registry https://beispiel.invalid/api/skills from /…/.claude/skill-trust-roots.yaml
$ skillctl trust add --registry https://beispiel.invalid/api/skills \
    --pubkey skill-registry-v2.pub --id reg-v2
added registry https://beispiel.invalid/api/skills to /…/.claude/skill-trust-roots.yaml
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml

registry: https://beispiel.invalid/api/skills
  identity_keys_authorized: from-registry
  governance_minimum:       green
  registry_keys:
    - id: reg-v2   issued: 2026-09-07
      pubkey (b64): LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=
```

Having **two** keys simultaneously in one registry row is the overlap
window; that list does not exist on the git path.

`trust add`, `trust list` and `trust remove` read and write only the local
file, so they were measured without a reachable instance. Re-admission
in step 3 was **not** measured.

During an incident, keep the window **as short as possible**: overlap
exists to avoid interrupting operation, not to give the old key a grace
period. A compromised key remains valid as long as it is pinned.

### ER1 registry `self`

No multiple-key pinning: flat `~/.claude/trust-roots.yaml` holds exactly
one `pubkey_b64`. Here overlap means publishing again under the new key,
sending every consumer the new fingerprint **over a second channel**,
and only then withdrawing the old key.

## 4. Repin

What every machine in the fleet must do after the operator rotates.
Again, this is backend-specific for the same reason as above.

### Git-backed registry: `peer add`

Two values come from the operator's public key, and the second must arrive
**over a different channel from the first**:

```bash
openssl pkey -pubin -in skill-registry-v2.pub -outform DER | tail -c 32 | base64 | tr -d '\n'
skillctl trust fingerprint skill-registry-v2.pub
```

Measured:

```
$ openssl pkey -pubin -in reg-v2.pub -outform DER | tail -c 32 | base64 | tr -d '\n'
LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=
$ skillctl trust fingerprint reg-v2.pub
sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27
```

The fingerprint is SHA-256 over exactly the 32 raw key bytes also passed
to `--pubkey`. Measured to establish that the two channels refer to the
same key:

```
$ openssl pkey -pubin -in reg.pub -outform DER | tail -c 32 | shasum -a 256
3b2dc6afd3fa2901346a6f0683814babb99144d07cfa53db5a80c53eada1e218  -
$ skillctl trust fingerprint reg.pub
sha256:3b2dc6afd3fa2901346a6f0683814babb99144d07cfa53db5a80c53eada1e218
```

Then, on every machine:

```bash
skillctl peer ls                              # was ist heute gepinnt
skillctl peer rm <name>                       # das alte Pin weg
skillctl peer add <name> gitlab://<host>/<gruppe>/skill-registry \
  --pubkey <raw-b64> --pin sha256:<hex> \
  --signer id:<reviewer>@<org>:<reviewer-raw-b64>
skillctl peer verify <name>                   # Trockenlauf, installiert nichts
```

Measured with a `gitlab://` locator:

```
$ skillctl peer add kup-registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs= \
    --pin sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27
pinned peer "kup-registry" → gitlab://<host>/<gruppe>/skill-registry
  fingerprint: sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27 (matched)
  signer:      (none pinned: only this registry key may attest)
  pull with:   skillctl pull --registry gitlab://<host>/<gruppe>/skill-registry
$ echo $?
0
```

The `(matched)` is the purpose of the second channel: the fingerprint
is checked, not merely logged. Measured with an incorrect pin:

```
$ skillctl peer add wrong gitlab://<host>/<gruppe>/anderes-registry \
    --pubkey LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs= \
    --pin sha256:0000000000000000000000000000000000000000000000000000000000000000
peer add: fingerprint mismatch (pinned sha256:0000…, key hashes to sha256:9c37af1780…)
$ echo $?
1
```

**`--signer` is not optional once publisher and reviewer use different
keys.** Otherwise, the attestation exists in the repository but does not
count. Measured using the same peer once without and once with the
reviewer pinned:

```
$ skillctl peer verify live            # ohne --signer gepinnt
peer "live" (local:///…/probe/live.git)  gov-min=green  fp=sha256:3b2dc6afd3fa…
  would-verify (pass §7 gauntlet): 0
  rejected: 1
    ✗ demo-skill@1.0.0  gate 4: no attestation at or above the trust-roots governance_minimum: no signed attestation found for this digest
$ echo $?
1

$ skillctl peer verify live            # mit --signer id:reviewer@probe:<raw-b64>
peer "live" (local:///…/probe/live.git)  gov-min=green  fp=sha256:3b2dc6afd3fa…
  would-verify (pass §7 gauntlet): 1
    ✓ demo-skill@1.0.0  gov=green
$ echo $?
0
```

The exit code is therefore usable as a script gate: `peer verify` returns
1 as soon as even one bundle is rejected.

### Git-backed registry without a peer pin: flat `trust-roots.yaml`

If the locator is not pinned as a peer, `pull` reads **flat**
`~/.claude/trust-roots.yaml`. This is not the file written by `trust add`,
and `trust list` does not display it. This content was measured to allow
a pull to succeed:

```yaml
registry: local:///…/probe/live.git
pubkey_b64: jUndusQ7uIdfHjFbhY3pNMc8Y/oMDoMjDZyGXo94dWg=
fingerprint: sha256:3b2dc6afd3fa…
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:reviewer@probe
    pubkey_b64: qbCDIlwrx8jhGKNbiHjNHrdUxILfnD2hYjlnvr8NBlY=
```

With exactly this file, pull ends with `staged=1  skipped=0` and exit 0;
the measurement is in
[Operations runbook: backup](ops-registry-backup-restore.de.md#prüfung-4-braucht-eine-voraussetzung-sonst-misst-sie-den-prüfenden).

If the file is absent and no peer is pinned, `pull` exits 2 before any
gate runs:

```
$ skillctl pull --registry local:///…/skills.git --skill demo-skill \
    --install --trust-mode --dry-run-install
pull: load trust-roots: trust-roots: open /…/.claude/trust-roots.yaml: open /…/.claude/trust-roots.yaml: no such file or directory
       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh), or pin the peer with `skillctl peer add`.
$ echo $?
2
```

The path appears twice in that line; this was measured and is not a
transcription error.

### HTTP registry: `trust add`

```bash
skillctl trust list                      # was ist heute gepinnt
skillctl trust add --registry https://<host>/api/skills --pubkey <neu>.pub --id <registry>-v2
skillctl trust remove --registry https://<host>/api/skills   # entfernt ALLE Schlüssel, siehe Abschnitt 3
skillctl trust fingerprint <datei>.pub   # Abgleich über den zweiten Kanal
```

**The fingerprint never travels over the same channel as the key.**
Sending a new key by email and its fingerprint in the same message does
not exclude an attacker capable of writing that message.

## 5. Check the fleet

On every affected machine, in this order:

```bash
# 1) Widerrufe abholen (HTTP-Registry mit signiertem Widerruf-HEAD)
skillctl revoke feed --registry https://<host>/api/skills          # Zustand: das ist die Vorgabe
skillctl revoke feed --refresh --registry https://<host>/api/skills

# 1b) dezentral: signierte Widerrufe der gepinnten Peers einsammeln
skillctl revoke feed --gossip

# 2) alle installierten Skills gegen die neue Vertrauenslage prüfen
skillctl verify --all --json

# 3) erst wenn Schritt 2 verstanden ist: Nichtbestehende aussortieren
skillctl verify --all --quarantine
```

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

The flag is accepted and behaves like invocation without it: status
retrieval **is** the default; `--status` merely makes it explicit.
A binary predating `b9a79d2` still returns the old exit 2; in that case
the behavior of your binary applies.

**Status retrieval exits 1 when the remote is unreachable.** Measured
against a nonexistent name:

```
$ skillctl revoke feed --registry https://<unerreichbar>/api/skills
skillctl revoke feed: fetch failed: Get "https://<unerreichbar>/api/skills/revocations/head": dial tcp: lookup <unerreichbar>: no such host
$ echo $?
1
```

**Refresh responds differently depending on machine state, which is
where monitoring gets designed incorrectly.** What matters is whether
flat `~/.claude/trust-roots.yaml` exists: it makes a machine *managed*.
Both cases measured against the same unreachable name:

```
$ ls ~/.claude/trust-roots.yaml            # Datei FEHLT: unverwaltet
ls: /…/.claude/trust-roots.yaml: No such file or directory
$ skillctl revoke feed --refresh --registry https://<unerreichbar>/api/skills
refreshed: 0 revoked digest(s), epoch=0 issued_at="" online=false
$ echo $?
0
```

```
$ ls ~/.claude/trust-roots.yaml            # Datei DA: verwaltet
/…/.claude/trust-roots.yaml
$ skillctl revoke feed --refresh --registry https://<unerreichbar>/api/skills
refreshed: 0 revoked digest(s), epoch=0 issued_at="" online=false
skillctl revoke feed --refresh: revocation unavailable under managed trust roots (fail-closed, exit 22): revoked-set unavailable under managed trust roots and no fresh cache (fail-closed)
$ echo $?
22
```

On the **unmanaged** machine, refresh reports success despite reaching
nothing; all the information is in `online=false`, and monitoring reading
only the exit code sees nothing. On the **managed** machine, the tool
fails closed with exit 22 once no fresh cache limits staleness; during
that grace window it remains at exit 0 with `online=false`.

The monitoring rule is therefore: alert on `online=false` **and** exit 22,
not the exit code alone. To ask "is my revocation HEAD fresh", use status
retrieval, whose exit 1 is independent of managed state.

With `--json`, `verify --all` produces a stable report. Measured on a
machine with no installed skills, complete with its introductory line:

```
$ skillctl verify --all --json
skillctl verify --all: no installed skills at /…/.claude/skills (nothing to sweep)
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  "verified": 0,
  "quarantined": 0,
  "unverified": 0,
  "skipped": 0,
  "entries": null
}
$ echo $?
0
```

The introductory line goes to **stdout**, not stderr, measured using
`2>/dev/null`. A consumer therefore starts at the first `{` line; details
are in [Monitoring and alerting](ops-monitoring.en.md).

`--quarantine` moves only **managed** skills that fail the trust path into
the quarantine directory. The run has a time budget (`--budget`, default
60s); anything it does not reach is `unverified` and **never** moved into
quarantine. A report with `unverified > 0` is therefore not a clean bill
of health, but an unanswered question.

**What is NOT possible here.** There is no push to the fleet. No command
in this tool reaches another machine. Every machine must run
`revoke feed --refresh` and `verify --all` itself, through a hook, launchd,
cron or a person. For a fleet-level statement, collect the `--json`
outputs; see [Monitoring and alerting](ops-monitoring.en.md).

## 6. Tokens, not keys

If a **token** is also affected, follow the other procedure:

1. Revoke it in GitLab. This acts immediately, without action by the
   machine. It is the only place that truly matters.
2. Run `skillctl token rm --backend gitlab --host <host>` on every machine
   that held it. This is hygiene, not a security measure.
3. Fill the token-register row's "Revoked on" column
   ([part C](ops-registry-tokens.de.md#teil-c-das-token-register)).
4. Issue a new token following part A or part B.

`skillctl token list --host <host>` then shows what remains stored on the
machine, **without** printing a token. The useful column is the source:
a set environment variable overrides protected storage, and a forgotten
`export` survives every `token rm`.

## 7. Ordered checklist

| # | Step | Command |
|---|---|---|
| 1 | Establish scope | `registry ls`, `registry show`, `gate-stats --since 168h` |
| 2 | Revoke affected digests | `publish --revoke …` or `revoke <digest> …` |
| 3 | Confirm revocation | `registry ls` shows `REVOKED` |
| 4 | New key pair | `keygen --out …` |
| 5 | Repin | https: `trust add …`, retain the old pin during the window · git: `peer rm …` then `peer add …`, in that order |
| 6 | Re-admit during the window | `publish …` (https; git has no overlap window for the registry key) |
| 7 | Remove old pin | https: `trust remove …`, then set the new pin again · git: already done in step 5 |
| 8 | Fingerprint over a second channel | `trust fingerprint …`, same command for both backends |
| 9 | Update the fleet | `revoke feed --refresh` (exit 22 on managed machines is a finding, not a bad invocation), `verify --all` |
| 10 | Quarantine failures | `verify --all --quarantine` |
| 11 | Update the token register | `OPS/token-register.md` |

## 8. What this runbook does not solve

**No fleet view.** There is no list of "who installed what" unless
consumers used `pull --emit-installed`. Incident scope is an organizational
question.

**No alert.** Nothing automatically reports that a revocation arrived.
The `revoke feed` must be fetched. See
[Monitoring and alerting](ops-monitoring.en.md).

**No expiration warning.** Neither GitLab nor `skillctl` warns before a
token expires; the date is not stored in a token. That is why the register exists.

**No retraction.** Revocation is a new signed event, not deletion.
This is deliberate: a timeline from which information can disappear is
worthless as evidence. An erroneous revocation is corrected by a new
admission under a new version, not by taking it back.

## Related runbooks

| Runbook | Purpose |
|---|---|
| [Operations routine: access tokens](ops-registry-tokens.en.md) | Who obtains which token and what happens when someone leaves |
| [Registry backup and restore](ops-registry-backup-restore.en.md) | Backup per backend, with restoration rehearsal |
| [Monitoring and alerting](ops-monitoring.en.md) | What is observable today and what is not |
