# Operations runbook: registry backup and restore

Sprachen / Languages: [Deutsch](ops-registry-backup-restore.de.md) | [English](ops-registry-backup-restore.en.md)

How to back up and restore a skill registry, per backend, with a rehearsal
that makes restoration verifiable and the prerequisite without which that
rehearsal measures the verifier instead of the restore.

Audience: the registry operator.

**How much of this runbook has been measured.** Blocks introduced as
"Measured" were executed on 2026-09-07 against the binary, a throwaway
`local://` registry and a throwaway `$HOME`. Paths (`/…/`) and digests
(trailing `…`) are shortened; any further omissions are marked by a line
`[…]`. For the ER1 registry `self`, only the tool's responses **without**
a reachable instance were measured, namely the refusals in section 4;
no ER1 instance was available.

## The core rule in one sentence

**A git-backed registry is a bare repository. Backup is
`git clone --mirror`; restoration is the same command in reverse.**

Everything else follows: for `local://`, `gitlab://` and `github://`,
standard tools provide a complete, verifiable backup. For the ER1 registry
`self`, they do not; section 4 explains the alternatives.

| Backend | Backup | Complete? |
|---|---|---|
| `local://<pfad>` | `git clone --mirror` | Yes: refs, objects, tags, signatures |
| `gitlab://<host>/<gruppe>/<projekt>` | `git clone --mirror` **plus** manual recording of project settings | Content yes, settings no |
| `github://…` | Same as GitLab | Same as GitLab |
| `self` (ER1) | No registry export in the tool, see section 4 | No |

## Why not simply copy the directory

Running `cp -r` over a bare repository receiving writes produces a backup
with partly written objects, discovered only during restoration.
`git clone --mirror` reads through git's object layer and is protected
against a concurrent push. Additionally, `git` checks every object's
checksum during cloning: a completed backup is therefore also verified.

## 1. Backend `local://`

### Back up

```bash
git clone --mirror <registry>.git <backup>/<registry>-$(date +%F).git
```

Measured on 2026-09-07:

```
$ git clone --mirror /…/probe/skills.git /…/probe/backup-skills.git
Klone in Bare-Repository '/…/probe/backup-skills.git' ...
Fertig.
```

Update an existing backup using `git -C <backup>.git remote update` rather
than creating another clone; as a mirror, it fetches all refs.

### Restore

```bash
git clone --mirror <backup>/<registry>-<datum>.git <registry>.git
```

### The trap after restoration

The restored clone points back to the backup, as a mirror:

```
$ git -C <registry>.git config --get remote.origin.url
/…/probe/backup-skills.git
$ git -C <registry>.git config --get remote.origin.mirror
true
```

A `git push` in this repository would therefore **write the production
registry's state into the backup**. That is exactly the wrong direction
if restoration was incomplete. Restoration must therefore include this final step:

```bash
git -C <registry>.git remote remove origin
```

### Additionally: the single-file snapshot

For transport without a git server, an air gap or a handover to a reviewer:

```bash
skillctl registry export --registry local://<registry>.git --out skills.bundle
```

Measured:

```
$ skillctl registry export --registry local:///…/probe/skills.git --out /…/probe/skills.bundle
exported registry snapshot: /…/probe/skills.bundle
  hand it to a peer; they review + verify with:
    skillctl registry ls --registry local:///…/probe/skills.bundle
    skillctl pull --registry local:///…/probe/skills.bundle   # §7 gauntlet verifies against THEIR trust roots
$ echo $?
0
```

A `.bundle` is a **readable** snapshot of every ref in one file; it supports
reading and pulling, but not publishing into it. It is therefore a complete
backup and unsuitable as an operational registry. Restore with:
`git clone --mirror skills.bundle <registry>.git`.

## 2. Backends `gitlab://` and `github://`

### Back up

Content is handled identically, using a URL instead of a path:

```bash
git clone --mirror https://<host>/<gruppe>/skill-registry.git \
  <backup>/skill-registry-$(date +%F).git
```

If cloning requires a token, use the **read token** from
[part A of the token routine](ops-registry-tokens.de.md#teil-a-eine-mitarbeiterin-richtet-ihre-maschine-ein-lesen).
Backup is a read operation; there is no reason to use the write token.

### What the clone does NOT include

This is what is missed during a real incident. A `--mirror` clone contains
refs and objects, nothing else. These settings must be restored manually
and therefore recorded **in writing** alongside the backup:

| Setting | Why it matters |
|---|---|
| **Default branch** (`main`) | Without it, `skillctl` reads an empty registry without error. See below. |
| Project Access Token (`skillctl-publish`, Maintainer, `write_repository`) | Without it, nobody can publish. The token itself cannot be backed up; issue a new one. |
| Members and roles | Who may read determines the registry's reach. |
| Branch protection on `main` | Prevents writes bypassing history. |
| Visibility (private / internal) | An accidentally public registry is an incident of its own. |

Token rows already belong in the token register
([part C](ops-registry-tokens.de.md#teil-c-das-token-register)); keep the
other four alongside it.

### Restore

```bash
# 1) leeres Projekt auf dem Server anlegen (ohne README, ohne Initialisierung)
# 2) Inhalt zurückspiegeln
git -C <backup>/skill-registry-<datum>.git push --mirror \
  https://<host>/<gruppe>/skill-registry.git
# 3) Standard-Branch im Projekt auf `main` setzen
# 4) Project Access Token neu ausstellen, Registerzeile schreiben
# 5) Mitglieder, Branch-Schutz, Sichtbarkeit nachziehen
```

**Step 3 is not optional.** `git push --mirror` transfers refs, not `HEAD`.
Measured against a local target whose default branch was `master`, while
the registry uses `main`:

```
$ git -C <quelle>.git push --mirror <ziel>.git
 * [new branch]      main -> main
 * [new tag]         demo-skill/v1.0.0 -> demo-skill/v1.0.0
$ skillctl registry ls --registry local://<ziel>.git
(no skills in registry)
$ echo $?
0
```

The data arrived completely; `skillctl` simply cannot find it, and the
exit code is 0. After
`git -C <ziel>.git symbolic-ref HEAD refs/heads/main`, the same command
lists the bundle. In GitLab, use Project → Settings → Repository →
Default branch.

**Only the local case was measured here.** Clone and push over HTTPS
against a real GitLab instance have not yet been measured; they are the
same git command with a different remote, but that is reasoning rather
than evidence. Evidence comes from run D-8 in
[part D of the token routine](ops-registry-tokens.de.md#teil-d-der-nachweislauf-d-8).

## 3. Restoration rehearsal

A backup that has never been restored is an assumption. Rehearse on a
**copy**, never on the production registry.

Measured on 2026-09-07 against a throwaway registry with one admitted and
attested bundle:

```
$ git clone --mirror /…/probe/skills.git /…/probe/backup-skills.git
Klone in Bare-Repository '/…/probe/backup-skills.git' ...
Fertig.

$ rm -rf /…/probe/skills.git              # der Schadensfall

$ git clone --mirror /…/probe/backup-skills.git /…/probe/skills.git
Klone in Bare-Repository '/…/probe/skills.git' ...
Fertig.

$ skillctl registry ls --registry local:///…/probe/skills.git
skill                            version    latest digest                                                            gov      status
------------------------------------------------------------------------------------------------------------------------------------
demo-skill                       1.0.0      sha256:22a21798c2839aa9667cae701a95a1a5bbd76559e8f7ab2d7b4f69fa1a70a9b9  green    ok
$ echo $?
0

$ git -C /…/probe/skills.git config --get remote.origin.url
/…/probe/backup-skills.git
$ git -C /…/probe/skills.git remote remove origin
Hinweis: Ein Branch außerhalb der refs/remotes/ Hierachie wurde nicht gelöscht;
um diesen zu löschen, benutzen Sie:
  git branch -d master
$ git -C /…/probe/skills.git config --get remote.origin.url
$ echo $?
1
```

The digest in this output is **complete**, not shortened: `registry ls`
prints it in full, which is exactly what check 2 needs.

Acceptance criteria:

| # | Check | Expected |
|---|---|---|
| 1 | `skillctl registry ls --registry <wiederhergestellt>` | Same row count as before the incident |
| 2 | Digest per skill | **Character-for-character identical** to the pre-incident state |
| 3 | `skillctl registry show <name> --registry <wiederhergestellt>` | Same event sequence, including revocations |
| 4 | `skillctl pull …` **with the pre-incident trust roots** (see below) | Same outcome as before: `staged=1` per skill, exit 0, same digest |
| 5 | `git -C <wiederhergestellt> config --get remote.origin.url`, **after** `remote remove origin` | No output, exit 1; immediately after the mirror clone it still points at the backup, see the trap above |

Check 2 is the decisive one. A restore containing the bundles but different
digests has broken their signatures, and every machine in the fleet will
reject the registry from then on.

### Check 4 requires a prerequisite or it measures the verifier

Check 4 runs the same gates as a consumer, which means its outcome depends
**not only on the registry** but on the trust roots of the machine running
it. Three measured outcomes, all against the same correctly restored registry:

All three runs use the same command, with only `$HOME` changed:

```bash
skillctl pull --registry local://<wiederhergestellt> --skill demo-skill \
  --install --trust-mode --dry-run-install
```

```
# 1) HOME ohne trust-roots.yaml und ohne Peer-Pin
pull: load trust-roots: trust-roots: open /…/.claude/trust-roots.yaml: open /…/.claude/trust-roots.yaml: no such file or directory
       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh), or pin the peer with `skillctl peer add`.
$ echo $?
2

# 2) ein FREMDER Schlüssel gepinnt
    ❌ demo-skill@1.0.0  digest=sha256:22a21798c283…  [gate 1: envelope_signature does not verify against trust-roots] registry: envelope_signature does not verify
==> done. staged=0  skipped=1
[…]
$ echo $?
12

# 3) die Wurzeln von vor dem Schaden
    ✅ demo-skill@1.0.0  digest=sha256:22a21798c283…  gov=green  →  /…/skill-bundles/22a21798c283…/bundle.skb
==> done. staged=1  skipped=0
$ echo $?
0
```

The digest is identical in all three runs, including the rejected run:
gate 1 checks the signature, not the content. A `❌` therefore does not
prove that restoration lost the bytes.

Only the third run says anything about restoration. The first two describe
the verifier's machine. Check 4 is evidence only if two conditions hold:

1. It uses the **same** `~/.claude/trust-roots.yaml` or the same
   `skillctl peer add` pin as before the incident. A fresh `$HOME`, a
   different computer or a borrowed machine does not satisfy this.
2. The **pre-incident** outcome is recorded. "The gates pass" without that
   comparison value is an expectation, not evidence; a pull already stuck
   at gate 4 beforehand will remain stuck afterward.

If the rehearsal must run on a machine without those roots, record check 4
as **not assessed** and base acceptance on checks 1 through 3 and 5.
That is more honest than a green row that measures the verifier.

A useful schedule: rehearse whenever a registry key rotates and at least
quarterly, recording the date and output of checks 1 and 2.

## 4. Backend `self` (ER1): what is missing

**There is no registry export for `self`.** Measured on 2026-09-07:

```
$ skillctl registry export --registry self --out /tmp/x.bundle
registry export: --registry must be local://<path> (got "self")
$ echo $?
2

$ skillctl registry init --registry self
registry init: only local:// registries are created locally (got "self").
  For gitlab://github:// create the project on the server; for ER1 use the self tenant.
$ echo $?
2
```

`registry export` supports only `local://`. Consequently, this tool neither
creates nor backs up `self`. There are currently two ways to back up a
`self` registry, both partial:

**(a) Bundle by bundle with `export-bundle`.** This is what the tool can do.
It writes the transferable artifact/envelope pair and verifies the chain
before writing:

```bash
skillctl registry ls --registry self          # die Liste, die gesichert werden soll
skillctl export-bundle <name>@<version> --out <backup>/
# schreibt <name>@<version>.skb + <name>@<version>.skbmeta.json
```

This backs up the **artifacts**. It does **not** back up the timeline:
attestations and revocations are separate events in the ER1 context and
are absent from the pair. Restoring from these is reconstruction through
another `publish`, not restoration.

**(b) Back up on the ER1 side.** The registry `self` is the ER1 login's
`<sub>___skills` context. A complete backup therefore means backing up
the ER1 tenant; that belongs to operating aims-core, not `skillctl`.
This runbook does not describe it because it could not be measured here.

**The honest recommendation.** If you need a backup that can be restored
in an incident, operate a git-backed registry. `self` is intended for
personal use and small teams, and this limitation is stated here explicitly.

## 5. What this runbook does not solve

**No automatic backup.** `skillctl` backs up nothing by itself.
`git clone --mirror` belongs in a scheduled task (launchd, cron, a CI job),
and someone must check that it runs; see
[Monitoring and alerting](ops-monitoring.en.md).

**No backup of project settings.** The table in section 2 is a manual
checklist. Nothing checks whether it is maintained.

**No key backup.** A registry without its corresponding private key remains
readable but cannot be extended. Back up keys separately and offline;
losing one requires rotation, not restoration; see
[Incident Response](ops-incident-response.en.md).

**No backup for `self`.** See section 4. This is a gap in the tool, not an
operational omission.

## Related runbooks

| Runbook | Purpose |
|---|---|
| [Operations routine: access tokens](ops-registry-tokens.en.md) | Which token may fetch the backup |
| [Incident Response](ops-incident-response.en.md) | Compromised key, compromised registry |
| [Monitoring and alerting](ops-monitoring.en.md) | Available monitoring integration points |
