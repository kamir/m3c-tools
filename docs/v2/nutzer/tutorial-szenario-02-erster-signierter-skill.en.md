---
layout: default
title: "Tutorial, scenario 02: the first signed skill, reviewed by another person"
---

# Tutorial, scenario 02: the first signed skill

[Deutsch](tutorial-szenario-02-erster-signierter-skill.de.md) · [English](tutorial-szenario-02-erster-signierter-skill.en.md)

**Audience:** You built a skill locally with Claude Code and want to sign and publish
it for the first time. Your manager or a colleague reviews it beforehand.
The three roles here are **employee**, the author; **Alice**, reviewer and publisher;
and **consumer**, somebody who installs the skill afterwards.

**What you will have:** A signed skill with an attestation signed by **another person**,
and a consumer who can install it because review happened, rather than because somebody
claimed it happened.

**Duration:** Part 1, the offline rehearsal without a server, takes about 15 minutes.
Part 2, the actual process, takes about an hour initially and minutes afterwards.

**Related documents:** [Scenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md),
one person and several machines; [manual](../referenz/manual-skillctl.md).

---

## The rule behind everything else

**Nobody may approve their own skill.** The author seals it, another person certifies it.
There are two keys held by two people. All complexity here follows from this rule,
which makes the resulting evidence meaningful.

Do not confuse these two concepts:

- **Author intent**, `--author-intent green`, is an advisory statement by the author.
  The verifier **ignores** it. It costs nothing and proves nothing.
- **Attestation**, `skillctl publish --attest` through ER1 or `skillctl attest` against
  HTTP, is a reviewer's signed verdict on a particular digest. It is binding.
  Without it, every installation fails with exit `13`.

---

## Part 0: prerequisites BEFORE signing

Seven points. The first three are obvious; missing any of the other four makes
the initial attempt fail with a hard-to-understand error.

| # | Requirement | Check | Who |
|---|---|---|---|
| 1 | `skillctl` from a **signed release**, not a source-tree build, with the **same** version on every participating machine | `skillctl version` says `skillctl/vX.Y.Z`, not `dev` | Everyone |
| 2 | Own keypair, private part with mode `0600` | `skillctl keygen --out <pfad>` | Employee, Alice |
| 3 | Identity ID in the form `id:<name>@<org>`, stamped into each signature and not changeable later without consequences | Agreement | Employee, Alice |
| 4 | A **writable registry**: for Git, an empty repository and a Project Access Token for the publisher, not a Deploy Token; for HTTP, a registered server-side identity too, otherwise `19 identity_mismatch` | `skillctl registry ls --registry <locator>` responds | Registry operator |
| 5 | Reviewer is **not** the author and has an **independent** key | Agreement, following the rule above | Alice |
| 6 | Git: locator and token variables set. ER1: login and server-side room membership, for which there is **no** `skillctl` verb | `echo $REG`, `skillctl login --status` | Everyone |
| 7 | Each party confirmed the other's fingerprint over a **second channel** | Phone, video call, in person | Employee, Alice, consumer |

Point 7 is easiest to skip. A public key arriving with a bundle proves nothing because
it followed the same unverified route. Only a pin confirmed beforehand over another
channel makes transport-independent trust possible. A pin without a channel change is no pin.

One requirement is deliberately absent: your skill need not be perfect. It must be reviewable.

---

## Part 1: rehearsal (offline, no server, 15 minutes)

This needs no registry, login or network. It walks through the mechanics so that you
recognize refusals during the real process. Everything happens in a working directory;
your real `~/.claude/` remains untouched.

### 1.1 Working directory and a tiny skill

```bash
export WS="$HOME/skillctl-uebung"
rm -rf "$WS" && mkdir -p "$WS"/{keys,src/hello-kup/scripts} && cd "$WS"

cat > src/hello-kup/SKILL.md <<'MD'
---
name: hello-kup
version: 0.1.0
description: Minimaler Uebungsskill fuer die Publisher-Kette, schreibt eine Datei nach ./out.
---

# hello-kup

Schreibt einen Gruss nach ./out/hello.txt. Kein Netzwerk, keine Secrets.
MD

cat > src/hello-kup/scripts/hello.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./out
echo "hello from hello-kup" > ./out/hello.txt
cat ./out/hello.txt
SH
chmod +x src/hello-kup/scripts/hello.sh
```

### 1.2 Two keys, two roles

```bash
skillctl keygen --out "$WS/keys/mitarbeiter"
skillctl keygen --out "$WS/keys/alice-reviewer"
ls -l "$WS/keys"
```

Expected: four files, with `.priv` permissions `-rw-------`.
Broader permissions make `sign` deliberately refuse later.

> Use absolute paths. For a relative path, `keygen` warns "relative path; resolving
> against CWD", and you may later find the key somewhere other than expected.

### 1.3 Pack and sign

```bash
skillctl pack \
  --skill ./src/hello-kup \
  -o hello-kup@0.1.0.skb \
  --name hello-kup \
  --version 0.1.0 \
  --summary "Uebungsskill" \
  --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out"

SIGN_OUT=$(skillctl sign \
  --key "$WS/keys/mitarbeiter.priv" \
  --identity-id id:mitarbeiter@kup \
  hello-kup@0.1.0.skb)
echo "$SIGN_OUT"

DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "DIGEST=$DIGEST"
```

> **The trap everybody encounters once.** `pack` prints `bundle_digest: sha256:…`,
> whereas `sign` prints `digest: …`; **the two values differ**. From now on,
> the signature filename, `attest` argument and `--digest` for `publish` and
> `revoke` all need **the value from `sign`**. The value from `pack` is the
> manifest digest, not the digest of the bundle bytes.

### 1.4 The author checks their own signature

```bash
skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" hello-kup@0.1.0.skb
echo "rc=$?"
```

Expected: `OK: signature verified`, `rc=0`.

### 1.5 Reproducibility check

Packing twice must produce identical bytes. Otherwise the skill contains something
time-dependent, and a signature cannot reliably describe its content.

```bash
skillctl pack --skill ./src/hello-kup -o probe.skb --name hello-kup --version 0.1.0 \
  --summary "Uebungsskill" --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out" >/dev/null
shasum -a 256 hello-kup@0.1.0.skb probe.skb
rm -f probe.skb
```

Expected: the same hash twice.

### 1.6 The author's readiness gate

Before handing anything to somebody else, run the self-check.
The skill must be in its normal location:

```bash
mkdir -p "$WS/home/.claude/skills/hello-kup"
tar -xzf hello-kup@0.1.0.skb -C "$WS/home/.claude/skills/hello-kup"
HOME="$WS/home" skillctl propose hello-kup --dry-run --intent green
```

Output: a table of eleven checks. In this exercise, `#9 smoke-test marker` fails
because `tests/smoke.sh` is absent. This is intentional: the gate identifies what
is missing before somebody spends review time on it.

> Two points: the exit code carries the verdict even with `--dry-run`.
> `0` means passed; `2` means the gate held. `--dry-run` only omits registry registration.
> An earlier version claimed `--dry-run` always returned `0`. That was wrong;
> a script relying on it would have treated every refusal as success.
> Also, `tar -xzf` is only an exercise shortcut here: a manually unpacked skill
> is invisible to `skillctl verify`, see Part 3.3.

### 1.7 The two refusals you need to recognize

First, the accident: somebody changes the bundle after signing.

A signed bundle arrives as the file **and** its signature. Copy both, then change the bytes.

```bash
cp hello-kup@0.1.0.skb kaputt.skb
for sig in hello-kup@0.1.0.skb.*.author.sig; do
  cp "$sig" "kaputt.skb.${sig#hello-kup@0.1.0.skb.}"
done
printf '\xff' | dd of=kaputt.skb bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" kaputt.skb
echo "rc=$?"
```

Expected: `bundle bytes changed after signing …`, `rc=10`. The message names both
digests: the current file hash and the digest covered by the adjacent signature.
That difference is the finding.

Previously this said `signature file not found`, `rc=1`. Technically true, but misleading:
the filename contains the digest, so changing bytes makes lookup miss the file.
The message reported a *side effect* of tampering rather than its cause, sending
users searching for a missing file instead of a broken seal.

When **no** signature is present, the tool now says exactly that:
`no signature found … It appears never to have been signed here`, `rc=1`.
This is a different situation requiring a different response: ask the sender for the signature.

Now the attack: the same byte change, but the attacker renames the original signature
to appear associated with the new bytes.

```bash
cp hello-kup@0.1.0.skb boese.skb
SIZE=$(wc -c < boese.skb | tr -d ' ')
printf '\xff' | dd of=boese.skb bs=1 seek=$((SIZE / 2)) count=1 conv=notrunc 2>/dev/null
BOESE_DIGEST=$(shasum -a 256 boese.skb | awk '{print $1}')
cp "hello-kup@0.1.0.skb.${DIGEST#sha256:}.author.sig" "boese.skb.${BOESE_DIGEST}.author.sig"

skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" boese.skb
echo "rc=$?"
```

Expected: `signature is invalid …`, `rc=11`. This is what cryptography detects:
a signature claiming to cover these bytes that does not.

**The distinction matters.** `1` means no signature exists for these bytes;
`11` means the supplied signature is wrong. Both are correct refusals for different
reasons. Merely running `verify-sig` against an altered bundle usually gives `1`
and documents something other than the intended claim.

### 1.9 Optional: the whole chain offline with a real registry

The rehearsal above ends at the signature. With ten more minutes, build the entire
registry on disk, using **the same code path as GitLab**, without a remote.
You will have seen the whole production process before using a server.

```bash
cd "$WS"
skillctl keygen --out "$WS/keys/alice-herausgeber"
skillctl registry init --registry "local://$WS/registry.git"

# Alice nimmt das Bundle des Mitarbeiters auf:
skillctl publish hello-kup@0.1.0 --bundle hello-kup@0.1.0.skb --version 0.1.0 \
  --registry "local://$WS/registry.git" \
  --key "$WS/keys/alice-herausgeber.priv" --identity id:alice@kup --yes

# Alice attestiert, mit dem ANDEREN Schlüssel:
skillctl publish --attest hello-kup@0.1.0 --digest "$DIGEST" --level green \
  --rationale "geprueft im Trockenlauf" \
  --registry "local://$WS/registry.git" \
  --identity id:alice-reviewer@kup --key "$WS/keys/alice-reviewer.priv" --yes

skillctl registry ls --registry "local://$WS/registry.git"
```

Expected: a line `hello-kup  0.1.0  sha256:…  green  ok`.

Now the consumer side in its own home:

```bash
mkdir -p "$WS/kunde/.claude"
cat > "$WS/kunde/.claude/trust-roots.yaml" <<YAML
registry: local://$WS/registry.git
pubkey_b64: $(skillctl trust fingerprint --b64 "$WS/keys/alice-herausgeber.pub")
fingerprint: $(skillctl trust fingerprint "$WS/keys/alice-herausgeber.pub")
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:alice-reviewer@kup
    pubkey_b64: $(skillctl trust fingerprint --b64 "$WS/keys/alice-reviewer.pub")
YAML

HOME="$WS/kunde" skillctl pull --registry "local://$WS/registry.git" --skill hello-kup \
  --install --trust-mode --dry-run-install --no-checkpoint
```

Expected: `✅ hello-kup@0.1.0 … gov=green` and a token valid for five minutes.
With `--confirm-install --dry-run-install-token <TOK>`, installation goes to
`$WS/kunde/.claude/skills/hello-kup/`, with `.m3c-provenance.json` and `.skillctl-attest.json`.

**Now the instructive variation.** Delete `signers:` from `trust-roots.yaml` and repeat pull:

```
❌ hello-kup@0.1.0  [gate 4: no attestation at or above the trust-roots governance_minimum]
```

The attestation is in the repository and valid, yet does not count: the consumer
has not pinned this reviewer. This is the system's intended statement.
Trust is established by the recipient, not the sender.

### 1.9b The same guided sequence in one command

Everything from Part 1 also exists as a script guiding you step by step,
explaining the purpose between steps:

```bash
make build-skillctl
./scripts/tutorial-smoke.sh --walk
```

It builds the same sandbox, follows the same chain through both refusals and pauses
after each step. Without `--walk`, it runs continuously and checks every exit code.
That form is a blocking part of `scripts/check-docs.sh`, preventing this tutorial
from silently becoming outdated.

> If `skillctl` is installed on `PATH`, note that the script prefers `./build/skillctl`
> when present, otherwise the `PATH` binary. An older installed binary does not
> understand `local://` and fails with
> `only ER1 registries ("self" / "er1://…") are supported here`.
> Choose the binary explicitly with `--skillctl <pfad>`.

### 1.8 Cleanup

```bash
cd ~ && rm -rf "$WS"
```

This removes the exercise registry too; it existed only under `$WS`.

The rehearsal is complete. You created a seal, verified it and observed two types
of refusal with real exit codes.

---

## Part 2: the real process (production: Git registry)

Three lanes: employee, Alice and consumer. **In production, the registry is a Git repository.**
The commands use `github://<owner>/<repo>`, the locator currently known to work reliably.
An internal GitLab instance, `gitlab://<host>/<gruppe>/<projekt>`, uses the same mechanism
and backend core. Once its synchronization works, exactly two things change:
the `--registry` value and token variable name. The ER1 route in Appendix A is the **test route**.

Git is a useful registry because its layout can be read and reviewed; each admission
and verdict is a commit, making history the audit log that would otherwise need building.

```
skills/<name>/<version>/bundle.skb     das versiegelte Bundle (sha256 == Digest)
skills/<name>/<version>/bundle.json    das entpackte Manifest, zum Nachlesen im Merge Request
events/<digesthex>/<seq>-<kind>.json   die signierten Ereignisse: admit, attest, revoke
```

The role separation also applies organizationally:

| Role | Person | Responsibility | Key |
|---|---|---|---|
| **Author** | Employee | Packs and seals | Own author key |
| **Approver and publisher** | Alice | Reviews, admits, attests | Publisher key and reviewer key |
| **Consumer** | Others | Pulls and installs | No key, only a registry pin |

The employee does **not** publish directly and needs no repository write access.
That separation is the purpose.

### Preparation: registry and token

A person creates the repository: empty, **private**, because it becomes the audit log,
with a protected default branch. Only the publisher may write to that branch.

```bash
# Schreibtoken, nur der Herausgeber braucht ihn (GitHub: PAT mit repo-Schreibrecht):
export M3C_GITHUB_TOKEN="<personal access token>"

# Optional, empfohlen: ein getrennter Lesetoken für Konsumenten,
# damit ein Pull nie den Schreibtoken überträgt.
export M3C_GITHUB_RO_TOKEN="<read token>"

export REG="github://<owner>/<repo>"
```

On macOS, both tokens can also reside in Keychain under `m3c-skillctl-github` and
`m3c-skillctl-github-ro`. `skillctl` reads the environment variable first, then Keychain.

> **For the internal GitLab instance**, once synchronization works, use
> `export REG="gitlab://<host>/<gruppe>/<projekt>"` with `M3C_GITLAB_TOKEN` and
> `M3C_GITLAB_RO_TOKEN`, Keychain services `m3c-skillctl-gitlab[-ro]`.
> Writes require a **Project Access Token** or PAT, **not a Deploy Token**:
> GitLab does not offer `write_repository` as a Deploy Token scope.
> For a self-hosted LAN instance without TLS, use `M3C_GIT_HTTP=1`.
> Everything else in this tutorial remains identical.

### Lane 1: the employee (author)

```bash
# M1. Einmalig: Schlüssel. Der private Teil verlässt diese Maschine nie.
mkdir -p ~/.config/m3c/skill-keys
skillctl keygen --out ~/.config/m3c/skill-keys/mitarbeiter

# M2. Fingerprint und Rohschlüssel, für Punkt 7 aus Teil 0.
skillctl trust fingerprint --b64 ~/.config/m3c/skill-keys/mitarbeiter.pub
skillctl trust fingerprint ~/.config/m3c/skill-keys/mitarbeiter.pub

# M3. Selbstprüfung, bevor Alice Zeit investiert.
skillctl propose <skill-name> --intent green
#   Exit 0: das Tor hält. Exit 2: es hat gegriffen, die FAIL-Zeilen abarbeiten.

# M4. Packen und signieren.
skillctl pack --skill ~/.claude/skills/<skill-name> \
  -o <skill-name>@<version>.skb \
  --name <skill-name> --version <version> \
  --summary "<ein Satz>" \
  --author-intent green --author-intent-rationale "<warum harmlos>"

SIGN_OUT=$(skillctl sign --key ~/.config/m3c/skill-keys/mitarbeiter.priv \
  --identity-id id:mitarbeiter@kup <skill-name>@<version>.skb)
DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "$DIGEST"

# M5. Selbst gegenprüfen.
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mitarbeiter.pub \
  <skill-name>@<version>.skb        # -> 0
```

**What to hand Alice, and how:**

| Item | Route | Reason |
|---|---|---|
| `<skill-name>@<version>.skb` **and** adjacent `.author.sig` | Any route: mail, share, ticket, merge request | Transport need not be trusted; both files are required |
| Digest from M4 | Same route, but **also read aloud** | Alice must check what the verdict covers |
| Your fingerprint from M2 | **Another channel**, once | Part 0, point 7 |
| What the skill does, which data it accesses and sends over the network | Text, ticket, merge request | This is what review evaluates, not the signature |

### Lane 2: Alice (approver and publisher)

```bash
# E1. Einmalig: zwei Schlüssel mit zwei Aufgaben.
skillctl keygen --out ~/.config/m3c/skill-keys/alice-herausgeber
skillctl keygen --out ~/.config/m3c/skill-keys/alice-reviewer

# E2. Die Autorensignatur des Mitarbeiters prüfen. Vorher muss der Fingerprint
#     aus M2 über den zweiten Kanal bestätigt sein.
skillctl verify-sig --pubkey ./mitarbeiter.pub <skill-name>@<version>.skb
echo "rc=$?"        # 0, sonst hier abbrechen und nichts aufnehmen

# E3. Über denselben Digest urteilen, den der Mitarbeiter genannt hat.
shasum -a 256 <skill-name>@<version>.skb
```

**E4, the actual review.** Not automatable, and the point of the exercise:

```bash
mkdir -p /tmp/review-<skill-name>
tar -xzf <skill-name>@<version>.skb -C /tmp/review-<skill-name>
ls -R /tmp/review-<skill-name>
cat /tmp/review-<skill-name>/SKILL.md
```

Check what the skill reads, writes and sends where. Does `SKILL.md` disagree with
its scripts? Does the bundle contain credentials, tokens or customer data?
Do declared dependencies match what is invoked? Finally, the question no signature
answers: **Do we want this skill running in the company?**

**E5. Admit.** Only now, and only if E2 and E4 were clean:

```bash
skillctl publish <skill-name>@<version> \
  --bundle <skill-name>@<version>.skb \
  --version <version> \
  --registry "$REG" \
  --key ~/.config/m3c/skill-keys/alice-herausgeber.priv \
  --identity id:alice@kup \
  --yes
```

Expected: `==> admitted: <name>/v<version>  transport=git  registry=<REG>`.
The repository then contains a bundle commit and another under `events/<digesthex>/`.

**E6. Attest with the reviewer key:**

```bash
skillctl publish --attest <skill-name>@<version> \
  --digest "$DIGEST" \
  --level green \
  --rationale "geprüft am <datum>; Autorensignatur id:mitarbeiter@kup verifiziert; kein Netzwerkzugriff; schreibt nur unter ./out" \
  --registry "$REG" \
  --identity id:alice-reviewer@kup \
  --key ~/.config/m3c/skill-keys/alice-reviewer.priv \
  --yes
```

**E7. Inspect the registry:**

```bash
skillctl registry ls --registry "$REG"
skillctl registry show <skill-name> --registry "$REG"
```

`registry ls` must show the skill with `gov=green` and `status=ok`.
An empty `gov=` or another status means the attestation is missing;
no consumer will be able to install it.

The three levels mean **green**, approved; **yellow**, conditional; **red**, rejected.
A `red` verdict means the process is working, not failing.

### Lane 3: the consumer

The consumer manually pins **the registry** in `~/.claude/trust-roots.yaml`:

```yaml
registry: github://<owner>/<repo>
pubkey_b64: <Alices Herausgeberschlüssel, roh, base64>
fingerprint: sha256:<über den zweiten Kanal bestätigt>
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:alice-reviewer@kup
    pubkey_b64: <Alices Reviewer-Schlüssel, roh, base64>
```

> **The shorter and better route.** Have `skillctl` write the same statement instead:
>
> ```bash
> skillctl peer add kup "$REG" \
>   --pubkey <Herausgeberschlüssel-b64> --pin sha256:<Fingerprint> \
>   --signer id:alice-reviewer@kup:<Reviewer-Schlüssel-b64> --quorum 1
> ```
>
> `peer add` **enforces** the out-of-band pin: it refuses when `--pin` does not match
> `--pubkey`, leaving no trust-on-first-use window. With a handwritten file,
> this comparison is your responsibility.
> `peer ls` then shows whose verdict you authorized.
>
> Without `--signer`, only the publisher key is permitted to attest again.
> That is appropriate when one person performs both roles with one key,
> precisely the arrangement you **do not** want when two people are involved.

```bash
# K1. Nur Lesetoken setzen. Ein Konsument braucht keinen Schreibzugriff.
export M3C_GITHUB_RO_TOKEN="<read token>"
export REG="github://<owner>/<repo>"

# K2. Plan ansehen (G-23, Schritt 1).
skillctl pull --registry "$REG" --skill <skill-name> \
  --install --trust-mode --dry-run-install --no-checkpoint
#   -> "✅ <name>@<version> … gov=green" und
#      "dry-run-install token (5-minute TTL): <TOK>"

# K3. Bestätigen (G-23, Schritt 2). Kein --key, kein --emit-installed.
skillctl pull --registry "$REG" --skill <skill-name> \
  --install --trust-mode \
  --confirm-install --dry-run-install-token <TOK> --no-checkpoint
```

Installation goes under `~/.claude/skills/<name>/`, with `.m3c-provenance.json` and
`.skillctl-attest.json` alongside it. Signed events are retained so that the runtime
gate can later verify against the pinned key offline.

Five gates run: envelope signature, not revoked, governance threshold, digest,
bundle signatures. Refusals mean:

| Line or code | Meaning | Who acts |
|---|---|---|
| `✅ … gov=green` | All gates passed | n/a |
| `gate 1: envelope` | Event not signed by the pinned key | Wrong pin or a repository other than expected |
| `gate 4: no attestation …` | No valid attestation at or above threshold | E6 missing, or reviewer absent from `signers:` |
| `gate 5: revoked` | Revoked | Do not install |
| `gate 2/3: digest` or `bundle sigs` | Bytes or signature mismatch | Obtain the bundle again; do not continue |

**When scripting:** A pull that rejects all bundles returns a typed process exit, such as `13` or `6`
and `NOT installing: N bundle(s) were skipped`. A pull finding **nothing** to do
returns `0`. In automation, inspect `✅` lines rather than the code alone.

### Offline route: build locally, upload later

Build the entire registry offline and mirror it to GitLab later.
The code path is the same; only the locator changes:

```bash
skillctl registry init --registry local://$HOME/skill-registry.git
skillctl publish <name>@<ver> --bundle <name>@<ver>.skb --version <ver> \
  --registry local://$HOME/skill-registry.git --key <herausgeber.priv> --identity id:alice@kup --yes
# ... admit + attest wie oben ...

git -C "$HOME/skill-registry.git" push --mirror https://github.com/<owner>/<repo>.git
```

For a handover without any server,
`skillctl registry export --registry local://<pfad> --out <datei.bundle>` produces
one file. The recipient pulls with `pull --registry local://<datei.bundle>`,
using the same gate sequence.

### What the consumer checks and what it does not

Be precise so that the chain does not promise more than it delivers:

- **Checked:** Alice admitted this bundle, through a publisher signature on the digest;
  a pinned reviewer key attested green; bytes are unchanged; no revocation for this
  digest is present in the repository.
- **Not checked:** The **employee's author signature**. The publisher signs both roles,
  author and registry, with their key; the employee's detached `.author.sig` is not
  carried into the repository. Authorship remains in the bundle and is protected
  from modification by Alice's signature. **Alice checked who authored the skill
  in E2; the consumer did not.**

E2 is therefore essential. The consumer trusts Alice; Alice verifies rather than assuming trust.

### After installation: remaining operational work

Know these two points before building operations around this:

- `skillctl verify <name>` now checks Git-installed skills itself. It binds on-disk
  content to the signed bundle and verifies the attestation against the pinned key.
  Expect `0` and a line identifying the skill's trust anchor. A later file change
  gives `10`. This requires the sidecars from managed installation; manually unpacked
  skills remain silent, see 3.3. It also requires the publisher pin in
  `trust-roots.yaml` or through `peer add`.
- With managed trust roots and no reachable revocation source, `skillctl verify --all`
  **fails closed** and would quarantine installed skills. Establish the revocation
  channel before routine sweeps; until then, run without `--quarantine` and read the output.

## Part 3: three limitations this tutorial makes explicit

### 3.1 A signature is not a safety certificate

It says "These bytes were sealed by this key," not that their content is harmless.
A perfectly signed skill can steal data. This is why Lane 2 includes a person
and attestation, and why E5 must not be abbreviated.

### 3.2 A signed .skb by mail is an emergency route

The full chain checks more than authorship: registry signature, bundle status,
governance level and tenant scope. Offline without a registry, only the author
signature can be verified. The portable route, `skillctl verify --bundle` with a
`BundleMeta` envelope or an `export-verification-kit`, requires prior registry admission.
Admission creates `<name>.skbmeta.json`; no command creates it locally.
A freshly packed, correctly signed bundle therefore cannot become such a kit;
the error now explains where the envelope comes from instead.

### 3.3 Manually unpacked skills are silent

`tar -xzf` works, but `skillctl verify <name>` then answers
"no .skb found … (was this skill installed by skillctl install?)" and
`verify --offline <name>` finds no retained metadata. The skill drops out of
`verify --all` and the gate. Unpacking is appropriate for inspection in E5,
not for installation.

---

## Part 4: acceptance

The process passes when all four points have output evidence rather than opinion:

| # | Criterion | Evidence |
|---|---|---|
| 1 | Employee sealed authentically | M5 and E2 `verify-sig` rc=0; M4 digest matches Alice's E6 verdict |
| 2 | Another person reviewed | E2 rc=0, Alice verified the author signature; E6 accepted with `--identity` different from M4; E7 shows `gov=green status=ok` |
| 3 | A third person can install | K2 shows `✅ … gov=green`; K3 installs with provenance file |
| 4 | A tampered bundle is rejected | Rehearsal 1.7, rc=11 with renamed signature |

Write evidence into a file that remains readable in six months:

```bash
{
  echo "Datum:      $(date -u +%FT%TZ)"
  echo "Host:       $(hostname)"
  skillctl version
  echo "Autor:      id:mitarbeiter@kup"
  echo "Registry:   $REG"
  echo "Herausgeber: id:alice@kup"
  echo "Reviewer:   id:alice-reviewer@kup"
  echo "Digest:     $DIGEST"
  echo "Fingerprint bestätigt über: <Telefon / Videocall / persönlich>, am <datum>"
  skillctl trust list
} | tee ~/szenario-02-evidenz.txt
```

Record the fingerprint-confirmation channel. A pin without evidence of **how** it was
confirmed is merely trust on first use under another name.

---

## Appendix A: the same process through ER1 self (test route)

ER1 `self` is for **testing** and individual users without Git registries.
Roles, review and the trust-roots file are unchanged; only three commands and
registry addressing differ.

```bash
# Einmalig auf jeder beteiligten Maschine:
skillctl login --base-url https://onboarding.guide
skillctl login --status

# E5 (Admit) und E6 (Attest) laufen gegen den eigenen ER1-Kontext:
skillctl publish <skill-name>@<version> --bundle <skill-name>@<version>.skb \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/alice-herausgeber.priv --identity id:alice@kup --yes

skillctl publish --attest <skill-name>@<version> --digest "$DIGEST" --level green \
  --rationale "geprüft am <datum>" \
  --registry self --er1-target prod --er1-context skills \
  --identity id:alice-reviewer@kup --key ~/.config/m3c/skill-keys/alice-reviewer.priv --yes

# Sichtbar machen, damit der Konsument es findet:
skillctl room share <skill-name> --room <raum-label> --yes

# K2/K3 beim Konsumenten, aus ALICES Kontext:
skillctl pull --registry self --er1-target prod --er1-context <alice-sub>___skills \
  --skill <skill-name> --install --trust-mode --dry-run-install --no-checkpoint
```

Use `registry: self` instead of the Git locator in `trust-roots.yaml`.
The `signers:` block remains required when publisher and reviewer use different keys.

Three differences from Git: `publish` **always** writes to the caller's context,
with `403` for another person's context; room membership is configured server-side
through the console, without a `skillctl` verb; the consumer must know the publisher's
exact context name.

## Appendix B: HTTP registry /api/skills and why it is not the main route here

Alongside ER1 `self`, the memory-layer `publish` / `pull` registry, aims-core exposes
a second registry API through `skill_registry` at `<base>/api/skills`.
This uses `skillctl trust add`, `install`, `attest` and
`~/.claude/skill-trust-roots.yaml`.

The registry client, `pkg/skillctl/registry/client.go`, and `skillctl attest`,
`cmd/skillctl/attest_cmds.go`, send no auth header. If an instance requires client
authentication, endpoints can answer `401 AUTH_REQUIRED`. The following workflow
requires endpoints without client authentication, such as an isolated local Docker
instance from `demo/kup-training/`. For authenticated production registry access,
use Part 2's Git registry route.

Where available, this is a cleaner variant of Part 2 because the reviewer posts
**directly**, without going through Alice as publisher:

```bash
# Reviewer, gegen eine Instanz, die den Endpunkt ohne Client-Auth bedient:
skillctl attest "$DIGEST" --level green \
  --rationale "geprüft am <datum>" \
  --reviewer-id id:alice@kup --author-id id:mitarbeiter@kup \
  --key ~/.config/m3c/skill-keys/alice-reviewer.priv \
  --registry https://<host>/api/skills

# Konsument:
skillctl trust add --registry https://<host>/api/skills --pubkey ./registry.pub
skillctl install <skill-name>@<version>
```

`--author-id` matters: it enables the reviewer-not-author check even if the admission
record is unreachable. If the registry returns `19 identity_mismatch`, Part 0 point 4
is unresolved: the reviewer identity is not registered there yet.
Use `POST /api/skills/identities`; the template is
`demo/kup-training/register-identity.sh`.

## Appendix C: Windows

- Paths: `%USERPROFILE%\.claude\skill-trust-roots.yaml` instead of `~/.claude/…`.
- A shipping Windows build intentionally ignores `$HOME` for security-sensitive paths
  and reads `%USERPROFILE%`. Part 1's sandbox must use `$env:USERPROFILE` there.
- Use `Get-FileHash -Algorithm SHA256` instead of `shasum -a 256`.
- Install through the PowerShell one-liner in [Quickstart §1](quickstart-skillctl.md#1-install).

---

## Where to go next

- Own skills on several machines: [scenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md)
- Practice until familiar: [Katas and Test Ride](tutorial-katas-und-test-ride.en.md)
- Every command, flag and exit code: [manual](../referenz/manual-skillctl.md)
