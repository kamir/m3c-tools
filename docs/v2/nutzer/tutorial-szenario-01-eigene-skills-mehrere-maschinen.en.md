---
layout: default
title: "Tutorial, scenario 01: your own skills on several machines"
---

# Tutorial, scenario 01: your own skills on several machines

[Deutsch](tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) · [English](tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md)

**Audience:** You use your own skills on more than one computer, such as a laptop,
desktop or Windows machine, and also want to use other people's signed skills.
You are the sole author of your own skills.

**What you will have:** A signing key that never leaves one designated machine,
your skills **installed as managed artifacts** on every other machine and therefore
verifiable later, somebody else's key correctly pinned, and a gate that blocks a
tampered skill before the agent loads it.

**Duration:** About 45 minutes for the first run, then minutes per skill.

**Related documents:** [Quickstart skillctl](quickstart-skillctl.md), for installation
and concepts; [manual](../referenz/manual-skillctl.md), for every command and flag;
[scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md), for two people and one approval.

---

## The model in four sentences

A skill is trusted because it is **signed**, not because it came from a particular server.
Whether the registry is Git or an ER1 context is therefore secondary: production uses
**Git**, internally GitLab or the customer's own instance, while ER1 is the test route.
Commands differ only in the `--registry` value. The registry transports artifacts and
records audit evidence; it is **not** part of the cryptographic verification path.
You trust precisely the public keys you pinned yourself. A valid signature says
"This is what this key sealed," never "This is safe."

---

## Part 0: the decision before the first command

**Choose one signing station.** Exactly one machine holds your private key.
Every other machine is a consumer. Each additional `.priv` copy expands the attack
surface, and the `0600` mode that `skillctl sign` requires fail-closed survives neither
Git nor most synchronization services. A key traveling through a synced folder will
eventually arrive as `0644`, and `sign` will rightly refuse it.

First check that the same actual release runs everywhere:

```bash
skillctl version        # muss skillctl/vX.Y.Z zeigen, nicht "dev"
```

If this says `dev`, you have a source-tree build rather than a signed release.
For installation, see [Quickstart §1](quickstart-skillctl.md#1-install).

---

## Part A: set up the signing station (once)

### A1. Generate a keypair

```bash
mkdir -p ~/.config/m3c/skill-keys
skillctl keygen --out ~/.config/m3c/skill-keys/alice
```

Expected output:

```
wrote ~/.config/m3c/skill-keys/alice.priv (mode 0600)
wrote ~/.config/m3c/skill-keys/alice.pub  (mode 0644)
```

`alice.priv` stays on this machine. `alice.pub` may go anywhere.

### A2. Record your fingerprint

You need it on every additional machine, in a form you can read aloud:

```bash
skillctl trust fingerprint --b64 ~/.config/m3c/skill-keys/alice.pub
skillctl trust fingerprint ~/.config/m3c/skill-keys/alice.pub
```

The first line is the raw public key in Base64, the `pubkey_b64` value; the second
is the fingerprint. Record both.

### A3. Pack and sign a skill

Assume a locally authored skill at `~/.claude/skills/mein-skill`.
It needs at least a `SKILL.md`.

```bash
cd ~/skills-workbench                       # ein Arbeitsverzeichnis, egal welches

skillctl pack \
  --skill ~/.claude/skills/mein-skill \
  -o mein-skill@1.0.0.skb \
  --name mein-skill \
  --version 1.0.0 \
  --summary "was der Skill tut" \
  --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out"

SIGN_OUT=$(skillctl sign \
  --key ~/.config/m3c/skill-keys/alice.priv \
  --identity-id id:alice@kup \
  mein-skill@1.0.0.skb)
echo "$SIGN_OUT"

DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "$DIGEST"
```

> **A trap you experience once.** `pack` prints `bundle_digest: sha256:…`, whereas
> `sign` prints `digest: …`; **these are two different values**. From now on, the
> digest needed for the signature filename, `--digest` in `publish` and `revoke`,
> and the argument to `attest` is **the one from `sign`**.
> The value from `pack` is the manifest digest.

The `$DIGEST` variable above captures exactly that value. `sign` is idempotent:
a second run over the same bytes writes the same signature, so repeating the block is safe.

### A4. Verify immediately

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/alice.pub mein-skill@1.0.0.skb
echo "rc=$?"          # 0 = OK: signature verified
```

Exit `0` means these bytes were sealed by this key. Exit `11` means the signature
does not match the bytes. Exit `10` means the file now hashes differently from what
the adjacent signature covers: it changed after signing. The message shows both
digests for comparison. Exit `1` means there is no adjacent signature at all;
the file was probably never signed here.

### A5. Publish and attest

From this point, you need an ER1 login. The skill enters your personal `self` registry,
from which your other machines pull.

```bash
skillctl login --base-url https://onboarding.guide
skillctl login --status

skillctl publish mein-skill@1.0.0 \
  --bundle mein-skill@1.0.0.skb \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/alice.priv \
  --identity id:alice@kup \
  --yes
```

The step almost everyone initially misses is this: **without a green attestation,
your own pull on the second machine fails with exit `13`, `governance_below_min`.**
The governance threshold is part of the chain. `--author-intent green` from A3 is
explicitly **advisory only** and ignored by the verifier. A signed attestation is binding.

For your own skills on your own machines, create a second key, the reviewer key:

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/alice-reviewer

skillctl publish --attest mein-skill@1.0.0 \
  --level green \
  --rationale "eigener Skill; kein Netzwerk; Datenpfade geprüft" \
  --registry self --er1-target prod --er1-context skills \
  --identity id:alice-reviewer@kup \
  --key ~/.config/m3c/skill-keys/alice-reviewer.priv \
  --yes
```

> **Scope of this arrangement.** Two keys held by one person provide **key separation**,
> not separation of duties. For your own skills on your own machines, this is appropriate:
> nobody but yourself can be deceived. Once a skill goes to others, it is no longer
> sufficient; [scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md) applies.

---

## Part A6: production variant, a Git registry instead of ER1

A1 through A4 stay unchanged. Only the two commands from A5 and the later pull change,
solely in their `--registry` value.

Once: create an empty **private** repository, which will hold the audit log,
and obtain a token with write permission.

```bash
export M3C_GITHUB_TOKEN="<personal access token>"
export REG="github://<owner>/<repo>"                # gitlab://<host>/<gruppe>/<projekt>, sobald der Sync steht

skillctl publish mein-skill@1.0.0 --bundle mein-skill@1.0.0.skb --version 1.0.0 \
  --registry "$REG" --key ~/.config/m3c/skill-keys/alice.priv --identity id:alice@kup --yes

skillctl publish --attest mein-skill@1.0.0 --digest "$DIGEST" --level green \
  --rationale "eigener Skill; kein Netzwerk; Datenpfade geprüft" \
  --registry "$REG" --identity id:alice-reviewer@kup \
  --key ~/.config/m3c/skill-keys/alice-reviewer.priv --yes

skillctl registry ls --registry "$REG"      # muss gov=green status=ok zeigen
```

On consumer machines, put the locator, `registry: gitlab://…`, instead of `registry: self`
in B2's `trust-roots.yaml`. Pull becomes
`skillctl pull --registry "$REG" --skill mein-skill --install --trust-mode …`; everything
else is identical. A **read token** is sufficient there, `M3C_GITHUB_RO_TOKEN` or
`M3C_GITLAB_RO_TOKEN` for GitLab. The write token stays on the signing station.

Two benefits justify this over ER1: the repository is readable, with
`skills/<name>/<version>/bundle.json` viewable in the browser and every verdict a commit;
the second machine needs no ER1 login, only a read token.

For a completely serverless route, `skillctl registry init --registry local://$HOME/skill-registry.git`
creates a bare repository on disk for publishing in the same way.
`git -C ~/skill-registry.git push --mirror https://github.com/<owner>/<repo>.git` uploads it later.

---

## Part B: the second and third machines

On every additional machine, **without** a private key.

### B1. Log in

```bash
skillctl login --base-url https://onboarding.guide
skillctl login --status
```

### B2. Pin your key

For ER1 `self`, the trust-roots file is written **manually**. This is intentional:
a pin is an explicit trust decision and should not happen incidentally.

```bash
cat > ~/.claude/trust-roots.yaml <<'YAML'
registry: self
pubkey_b64: <der Base64-Wert aus Schritt A2, Ihr Signierschlüssel>
fingerprint: sha256:<der Fingerprint aus Schritt A2>
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:alice-reviewer@kup
    pubkey_b64: <der Base64-Wert Ihres REVIEWER-Schlüssels aus A5>
YAML
```

The `signers:` block is mandatory if you attested with a **second** key in A5.
Attestations are checked against pinned signers; without this entry, only the signing
key is implicitly permitted to attest. Pull would otherwise fail despite an existing
attestation. If both roles use the same key, omit `governance_quorum` and `signers`.

For a Git registry, the same operation is shorter and safer because `peer add`
enforces the fingerprint comparison rather than leaving it to you:

```bash
skillctl peer add meins "$REG" \
  --pubkey <Signierschlüssel-b64> --pin sha256:<Fingerprint> \
  --signer id:alice-reviewer@kup:<Reviewer-Schlüssel-b64> --quorum 1
```

> **The two easily confused files.** `~/.claude/trust-roots.yaml`, flat and handwritten,
> applies to ER1 `self` and is read by `pull`.
> `~/.claude/skill-trust-roots.yaml` applies to HTTP registries, is written by
> `skillctl trust add --registry <URL> --pubkey <datei>` and read by `install`, `verify`,
> and `audit`. Filling the wrong file is the most common setup error, producing
> exit `12`, `registry_not_trusted`.

### B3. Pull and install in two steps

Installation follows G-23: first a plan with a short-lived token, then confirmation
that checks the plan against the **current** state again.

```bash
skillctl pull --registry self --er1-target prod --er1-context skills \
  --skill mein-skill --install --trust-mode --dry-run-install --no-checkpoint
```

The output shows what would be created or overwritten, ending with
`dry-run-install token (5-minute TTL): <TOK>`. Read the plan. Then:

```bash
skillctl pull --registry self --er1-target prod --er1-context skills \
  --skill mein-skill --install --trust-mode \
  --confirm-install --dry-run-install-token <TOK> --no-checkpoint
```

Five gates run: envelope signature, not revoked, governance threshold, digest,
bundle signatures. The skill is placed under `~/.claude/skills/mein-skill/`
with a `.m3c-provenance.json` provenance file alongside it.

### B4. Verify again

```bash
skillctl verify mein-skill
echo "rc=$?"        # 0
skillctl verify --all
```

> **Why not simply unpack?** A `.skb` is a tar.gz, so `tar -xzf` works.
> But a manually unpacked skill is then **silent**: `skillctl verify <name>` answers
> "no .skb found … (was this skill installed by skillctl install?)", and
> `verify --offline <name>` also finds no retained metadata. It therefore drops out
> of the `verify --all` sweep and the gate. Manual unpacking is an emergency route
> without a registry, Part C2, rather than an installation method.

---

## Part C: use somebody else's signed skills

These skills were signed by another person, called Bob below.

**First, a rule that avoids later trouble.** Do not pin multiple registries alongside
one another. Verify a third-party skill and **admit it into your own registry**,
re-admission, like an enterprise artifact mirror. Each machine keeps exactly one key,
one locator and one threshold. This is practical rather than cosmetic:
`trust-roots.yaml` holds exactly one registry entry. A file per origin, selected with
`--trust-roots` during pull, moves a security decision into the command line,
where it will eventually be mistyped.

### C0. First the pin, then the artifact

A public key arriving **with the bundle** proves nothing: it followed the same
unverified route. Have its fingerprint read aloud over a **second channel**, such as
a phone call, video call or in person, and compare character by character.
Only then can you say that the transport need not be trusted.

### C1. Route 1: re-admit into your own registry (standard)

You have Alice's role from [scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md):
approving a skill authored by somebody else.

```bash
# 1. Bobs Bundle und seine .author.sig entgegennehmen, Fingerprint vorher
#    über den zweiten Kanal bestätigt haben (C0).
skillctl verify-sig --pubkey ./bob.pub bob-skill@1.0.0.skb
echo "rc=$?"        # 0, sonst hier abbrechen

# 2. Ansehen, worüber Sie urteilen.
mkdir -p /tmp/review-bob && tar -xzf bob-skill@1.0.0.skb -C /tmp/review-bob
cat /tmp/review-bob/SKILL.md && ls -R /tmp/review-bob

# 3. In Ihr Registry aufnehmen und attestieren.
skillctl publish bob-skill@1.0.0 --bundle bob-skill@1.0.0.skb --version 1.0.0 \
  --registry "$REG" --key ~/.config/m3c/skill-keys/alice.priv --identity id:alice@kup --yes

skillctl publish --attest bob-skill@1.0.0 --digest "<Digest aus Bobs sign-Ausgabe>" \
  --level green --rationale "Upstream id:bob@m3c; Signatur verifiziert; Inhalt geprüft am <datum>" \
  --registry "$REG" --identity id:alice-reviewer@kup \
  --key ~/.config/m3c/skill-keys/alice-reviewer.priv --yes
```

Afterwards, **every** machine pulls it with the same command and pin as your own skills:

```bash
skillctl pull --registry "$REG" --skill bob-skill --install --trust-mode \
  --dry-run-install --no-checkpoint
```

You gain one source and one pin. `registry show bob-skill` records **who** made the
verdict and when: you. Bob's authorship remains visible in the bundle, while
responsibility for allowing it to run in your environment is explicitly assigned.

> **Exception, not the standard route.** On one machine, for a one-off experiment,
> you can pin a third-party registry directly: create another trust-roots file
> and pass `--trust-roots <datei>` during pull. Do not make this permanent or use
> it across multiple machines.

### C2. Route 2: through an ER1 room (test route)

Bob publishes into **his own** context and shares the skill into a common room.
You become a room member server-side through the onboarding.guide console;
there is no `skillctl` verb for this. Then pull from **his** context:

```bash
# Trust-Roots-Datei für Bobs Schlüssel, gleiche Form wie in B2
skillctl pull --registry self --er1-target prod --er1-context <bob-sub>___skills \
  --skill bob-skill --install --trust-mode --dry-run-install --no-checkpoint
# ... Plan lesen, dann mit --confirm-install und dem Token bestätigen
```

Important: **no** `--key` and **no** `--emit-installed`. You are only a consumer;
nothing should be written back into Bob's registry.

The workflow with separate author, reviewer and consumer roles is in
[scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md).

### C3. Route 3: HTTP registry (currently only without client authentication)

> **Read first.** `/api/skills` is aims-core's `skill_registry` module, on the same
> machine as ER1 but with another API. The HTTP registry client sends **no auth header**
> to this API. If your instance requires client authentication, it may answer
> `401 AUTH_REQUIRED`. This workflow requires endpoints without client authentication,
> such as an isolated local demo instance. For authenticated production registry
> access, use the Git registry route.

```bash
skillctl trust add \
  --registry https://<registry-host>/api/skills \
  --pubkey ./bob.pub \
  --id bob-2026

skillctl trust list
```

`trust list` prints the pinned key as Base64. Compare it with what Bob read aloud
on the phone. Then:

```bash
skillctl install bob-skill@1.0.0
echo "rc=$?"                     # 0 = installiert
skillctl verify bob-skill
```

On failure, the exit code tells you why:

| Code | Meaning | Action |
|---|---|---|
| `10` | Digest mismatch | Obtain the bundle again; do not continue |
| `11` | Invalid author signature | Obtain the bundle again; do not continue |
| `12` | Registry not in trust roots | Wrong file or wrong pinned key; see B2 |
| `13` | Governance below threshold | Green attestation missing; ask the publisher |
| `14` | `depends_on` unsatisfied | Provide the declared dependency |
| `17` | Revoked | Skill withdrawn; do not install |

### C4. Route 4: file transfer without a registry

If you receive only a `.skb` and signature file, the sole statement you can verify
offline is the **author signature**:

```bash
skillctl verify-sig --pubkey ./bob.pub bob-skill@1.0.0.skb
echo "rc=$?"        # 0 = von diesem Schlüssel versiegelt
```

Unpack only after exit `0`:

```bash
mkdir -p ~/.claude/skills/bob-skill
tar -xzf bob-skill@1.0.0.skb -C ~/.claude/skills/bob-skill
```

Be explicit about what is **missing**: governance level, revocation check, tenant scope
and later verifiability, see B4. This is an emergency route, not the standard.
The intended portable route, `skillctl verify --bundle` with a `BundleMeta` envelope,
requires that the bundle has passed through a registry once. Admission creates
`<name>.skbmeta.json`; `export-verification-kit` cannot create it, only build a kit
around it. The command now says so and names `skillctl registry show <digest>`
as the source.

---

## Part D: enable the gate on every machine

So far you verified when you remembered. The gate verifies when you forget.
It runs as a Claude Code `PreToolUse(Skill)` hook, verifies the chain **before**
loading a skill and refuses on uncertainty, fail-closed.

In Claude Code configuration, `settings.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Skill", "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

Do **not** run `verify-hook` manually. It reads the hook event from standard input;
interactive invocation therefore produces "unreadable hook event on stdin (fail-closed)"
and exit `2`. This is the intended refusal under uncertainty, not a malfunction.

Afterwards an agent cannot load a skill that fails the chain, even if it tries.
Inspect the gate's decisions here:

```bash
skillctl gate-stats --since 168h     # Entscheidungen der letzten Woche
```

Regularly, and after any suspicion:

```bash
skillctl verify --all
skillctl audit --source all --minimum-governance green
```

> **A measured limit to understand before scheduling this.** With managed trust roots,
> `verify --all` **fails closed** if no revocation source is reachable. With
> `--quarantine`, it would move newly installed skills. Run the sweep without
> `--quarantine` first and inspect its output until the revocation channel works.
> Verifying a **single** skill, `skillctl verify <name>`, does work for skills installed
> from Git: it binds the content to the signed bundle and verifies the attestation
> against the pinned key.

`audit` uses its own scale: `0` means everything is fine; `2`, at least one skill
unverified or below threshold; `3`, at least one broken skill.

---

## Part E: revocation

When one of your skills must be withdrawn:

```bash
skillctl publish --revoke mein-skill \
  --digest "$DIGEST" \
  --reason superseded \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/alice.priv --identity id:alice@kup --yes
```

Against Git, use `--registry "$REG"` instead of `--registry self --er1-target …`.
Revocation becomes another signed event under `events/<digesthex>/`, taking effect
on the next pull as `gate 5: revoked`, process exit `6`.

Other machines learn about a Git registry revocation at their next `pull` or `verify --all`. Both
verify the event against the pinned key and add the digest to a local set that only grows. From then
on `verify-hook` denies the skill and `verify <name>` exits `17`. `verify --all` reports verdict `17`
for the skill and exits `1`. Until that refresh the skill still loads. The installer registers an hourly service that runs `verify --all --json`; see [Scheduling](../../../tools/scheduling/README.md).
Revocation is signed and offline-verifiable; stale or rolled-back lists are
rejected rather than silently trusted, exit `22`.

---

## Finish: evidence to retain

Keep numbers rather than "it worked":

```bash
{
  echo "Datum:        $(date -u +%FT%TZ)"
  echo "Host:         $(hostname)"
  skillctl version
  echo "Fingerprint:  $(skillctl trust fingerprint ~/.config/m3c/skill-keys/alice.pub)"
  echo "Digest:       $DIGEST"
  skillctl trust list
  skillctl verify --all
  echo "verify --all rc=$?"
} | tee ~/szenario-01-evidenz.txt
```

Six months later, this file answers what actually held on that day.

---

## Windows

Everything above applies, with three differences:

- Paths: `%USERPROFILE%\.claude\trust-roots.yaml` and
  `%USERPROFILE%\.claude\skill-trust-roots.yaml`.
- A shipping Windows build deliberately ignores `$HOME` for security-sensitive paths
  because attackers can set environment variables. It reads `%USERPROFILE%`.
  Sandbox tricks based on `$HOME` therefore do not work there.
- Install through the PowerShell one-liner in [Quickstart §1](quickstart-skillctl.md#1-install).
  Choose **either** that route **or** the machine-wide installer, not both.

---

## Troubleshooting

| Symptom | Meaning | Remedy |
|---|---|---|
| `sign`: "insecure mode 0644" | Private key permissions too broad | `chmod 600 <key>.priv`; if it came through a sync folder, the signing station from Part 0 is the underlying answer |
| `pull` exit `12` | Wrong trust-roots file or key | Read B2: `trust-roots.yaml` for `self`, `skill-trust-roots.yaml` for HTTP |
| `pull` exit `13` | No green attestation | A5, second block |
| `publish` HTTP 403 | Publishing into somebody else's context | Publish only into your **own** `--er1-context skills` |
| `verify <name>`: "no .skb found" | Skill unpacked manually | Reinstall through `pull --install` or `install` |
| `verify-sig` exit `10`, "bundle bytes changed after signing" | Bytes changed after signing | Obtain the bundle again |
| `verify-sig` exit `1`, "no signature found" | No adjacent signature; probably never signed | Ask the sender for the `.sig` |

---

## Where to go next

- Two people, one approval: [scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md)
- Practice until familiar: [Katas and Test Ride](tutorial-katas-und-test-ride.en.md)
- Every command and flag: [manual](../referenz/manual-skillctl.md)
