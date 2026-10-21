# Operations routine: access tokens for the registry and skill repository

Sprachen / Languages: [Deutsch](ops-registry-tokens.de.md) | [English](ops-registry-tokens.en.md)

Who obtains which token, from where, where it is stored, and what happens
when someone leaves. Intended for real operation at a customer with its
own GitLab instance.

Audience: the person setting up a machine and the person operating the
registry. Each needs only their own section.

**Example instance.** Replace `git.example.com` with your own GitLab instance
and `<gruppe>` with your project group. The registry locator is

```
gitlab://git.example.com/<gruppe>/skill-registry
```

and `<gitlab-host>` in all commands below is accordingly
`git.example.com`. For an HTTPS instance, leave `M3C_GIT_HTTP` unset; this
variable is intended only for a LAN instance without TLS.

## The core rule in one sentence

**The token determines who may move the bytes. The key determines to whom
they are attributed.** They are separate, so assigning a token to a project
rather than a person does not weaken attribution.

The entire routine follows from this:

| | Obtained from | Owner | Reason |
|---|---|---|---|
| **Read** (`pull`, `verify`, `install`) | Employee's GitLab account | The person | Access automatically ends when the person leaves |
| **Write** (`publish`, `attest`) | Registry project settings | The project | The registry survives personnel changes |

The second row is the only departure from the most obvious solution; the
reason appears below under "Why write tokens are not personal".

## Part A: an employee sets up their machine (read)

Time: two minutes. No administrator rights required.

**1. Create a token in your own GitLab account.**

> Profile → Access Tokens → Add new token
> Name: `skillctl-lesen-<maschinenname>`
> Expiration date: set it, no more than 12 months
> Scopes: **`read_api`** and **`read_repository`**, nothing else

The token is displayed **once**. Never again afterward.

**2. Store the token.**

macOS and Windows, one command:

```bash
skillctl token set --backend gitlab --host git.example.com --read-only
```

Then paste the token and finish with Ctrl-D. **The token is read from stdin
and never appears on the command line**, therefore neither in `ps` nor in
shell history. It is stored in Keychain (macOS) or encrypted with DPAPI per
user account (Windows).

For an HTTP registry (`--registry https://…/api/skills`), the backend is
`registry` instead of `gitlab`.

Linux has no protected storage; the command says so and names the environment
variable rather than writing the token somewhere unprotected. The variable
is the usual choice for CI anyway:

```bash
export M3C_GITLAB_RO_TOKEN='<token>'      # Git-Registry
export M3C_REGISTRY_RO_TOKEN='<token>'    # HTTP-Registry
export M3C_REGISTRY_TOKEN_ORIGIN='https://registry.example.com'
```

`skillctl token list --host git.example.com` shows what is stored where,
**without printing the token**. The useful column is the source: a set
environment variable overrides protected storage, and a forgotten `export`
explains a failure that the stored token would not have caused.

**3. Verify.**

```bash
skillctl pull --registry gitlab://<host>/<gruppe>/<projekt> --skill <name> --dry-run-install
```

Expected: the gates pass. On `401`, since FR-0117 the tool explicitly says
whether **no** token was sent or the supplied token was **rejected**.
These are different errors with different next steps.

**4. Add a token-register entry.** One row, see part C.

## Part B: setting up the registry (write)

Performed by the registry operator, once per registry, not per person.

**1. Create the project.** An empty GitLab project, for example
`<gruppe>/skill-registry`. No README, license file or initialization:
step 4 mirrors the structure of a locally created registry.
`skillctl registry init` does **not** create the project and cannot do so;
it only understands `local://`.

**2. Create a Project Access Token.**

> Project → Settings → Access Tokens → Add new token
> Name: `skillctl-publish`
> Role: **Maintainer**
> Scopes: **`write_repository`**
> Expiration date: set it, no more than 12 months

**Not a Deploy Token.** GitLab does not permit `write_repository` as a
Deploy Token scope, and the default branch is protected at Maintainer level.
A Deploy Token fails on push, without an error explaining why.

**3. Store it as in part A**, but without `--read-only`, in the write tier:

```bash
skillctl token set --backend gitlab --host git.example.com
```

**4. Create the structure and mirror it upstream.**

`skillctl registry init` creates **only** a local registry. It refuses a
`gitlab://` locator before establishing any connection:

```
$ skillctl registry init --registry gitlab://git.example.com/<gruppe>/skill-registry
registry init: only local:// registries are created locally (got "gitlab://…").
  For gitlab://github:// create the project on the server; for ER1 use the self tenant.
$ echo $?
2
```

This is the division of responsibilities: GitLab creates the project, git
creates the structure. Follow the procedure that `registry init` itself prints:

```bash
# a) lokales Registry anlegen: ein bare-Repo mit dem Branch `main`
skillctl registry init --registry local://~/registry/skill-registry.git

# b) einmal in das leere GitLab-Projekt spiegeln
git -C ~/registry/skill-registry.git push --mirror \
  https://git.example.com/<gruppe>/skill-registry.git

# c) ab jetzt direkt gegen GitLab veröffentlichen
skillctl publish <name> --bundle <datei>.skb --version <v> \
  --registry gitlab://git.example.com/<gruppe>/skill-registry \
  --key <autor>.priv --identity id:<du>@m3c --yes
```

**The one place this silently goes wrong.** `git push --mirror` transfers
refs, not `HEAD`. If the GitLab project's default branch is not `main`,
`skillctl` sees an empty registry without reporting an error:

```
$ skillctl registry ls --registry <locator>
(no skills in registry)
$ echo $?
0
```

Exit 0 for a genuinely empty registry is correct; here it misleads because
the registry is not empty. Fix in GitLab: Project → Settings → Repository →
set the default branch to `main`. Locally the equivalent is
`git -C <ziel>.git symbolic-ref HEAD refs/heads/main`. Afterward,
`registry ls` lists the bundles.

**What has been measured here and what has not.** Steps (a) and (b) were
exercised against a local target on 2026-09-07: `registry init`, `publish`,
`push --mirror`, `registry ls` against the target, including the HEAD trap
above. Step (c), the `gitlab://` transport over HTTPS, is demonstrated only
by the D-8 evidence run in part D; until then it is reasoned, not measured.

## Why write tokens are not personal

The obvious approach would also perform writes through a personal account.
It has two consequences that become apparent later:

1. **The registry dies with the account.** When the person leaves, nobody
   can admit anything until someone identifies the cause. For read access
   this is intended; for write access it is an outage.
2. **It looks like attribution but is not.** The **signature** on the admit
   event records who admitted the bundle, not the token. A personal write
   token adds nothing to attribution and reduces availability.

The separation costs nothing: admission is still signed with a personal
key, and pull verifies that exact signature.

## What happens when personnel change

| Situation | Action |
|---|---|
| Employee leaves | None. Their read token ends with their account. |
| Machine is replaced | Create a new read token, revoke the old one in GitLab, replace the register row. |
| Registry operator changes | Rotate the Project Access Token; the project and all read tokens remain. |
| Token expired | GitLab does not announce it in advance. Hence part C. |
| Token compromised | Revoke it in GitLab. This is the only place that truly matters; the local entry is then obsolete. |

Revocation in GitLab takes effect immediately, without action by the machine.
Local deletion (removing the Keychain entry) is hygiene, not a security measure.

## Part C: the token register

Without a register, a token expires and nobody knows which one it was.
One row per issued token, in the maintenance repository at
`OPS/token-register.md` (path decided on 2026-09-06):

| Registry | Purpose | Owner | Issued | Expires | Revoked on |
|---|---|---|---|---|---|
| `gitlab://git.example.com/<gruppe>/skill-registry` | Read, Alice's laptop | Alice | 2026-09-06 | 2027-09-01 | n/a |
| `gitlab://git.example.com/<gruppe>/skill-registry` | Write, publish | Project | 2026-09-06 | 2027-09-01 | n/a |

No token value in the register, only the fact it exists. Readers should
know **what expires**, not **what credentials to use**.

Satisfies AC-14 of SPEC-0407 and REQ-3.15.

## HTTP Registry credential origin and migration

For the shared HTTP Registry read clients and `attest`, an environment token now
requires an independently configured `M3C_REGISTRY_TOKEN_ORIGIN`. Set it to the trusted
Registry origin, for example `https://registry.example.com`, before using either
`M3C_REGISTRY_TOKEN` or `M3C_REGISTRY_RO_TOKEN`. Comparison binds scheme, hostname and
effective port (HTTPS defaults to 443, HTTP to 80). The pin contains no credentials,
query, fragment or application path. It is never inferred from `--registry`, a
trust-roots default or `M3C_REGISTRY_URL`. Changing the target does not change the pin.

Migration: existing environment-token setups must add this origin explicitly.
Without a valid matching pin, read clients continue anonymously and never send the
environment bearer; `attest` fails before private-key loading, signing or HTTP.
Changing host, port or scheme requires a deliberately changed pin. Credentials are
sent only over HTTPS or explicit loopback HTTP. Read clients on plain HTTP outside loopback remain
anonymous and never query host credential stores. Attest requires HTTPS or loopback
HTTP before key loading even when no token is configured. Userinfo, query and fragment
are refused before token lookup. Host-bound native credentials remain available
when no selected environment token is configured; the existing read-only tier and
fallback order are retained. GitLab/GitHub credential-origin behavior and other
mutation transports have not been audited by this change.

`M3C_TOKEN_STORE=file` or `M3C_TEST_KEYCHAIN=0` explicitly disables native credential
reads, status probes, writes and deletes across artifactauth backends. Environment
resolution remains available. Native management returns a clear disabled error;
this does not implement a new file credential backend. With neither switch set,
normal platform behavior is retained. `M3C_ER1_KEYCHAIN` is not a global backend policy.

## Lookup order

If `skillctl` finds nothing, it continues anonymously. This is deliberate:
a public instance should work without setup.

```
Read:  RO environment -> RO host store -> WRITE environment -> WRITE host store -> anonymous
Write: WRITE environment -> WRITE host store -> anonymous
HTTP Registry environment tokens require M3C_REGISTRY_TOKEN_ORIGIN before lookup.
```

On a read path, the read token is looked up first; the write token is only
a fallback. If both are stored, a `pull` never sends the write token over
the connection.

## Part D: the D-8 evidence run

Perform once; afterward REQ-3.5 is confirmed outside a local repository.
Until then, every statement about the production path is a statement about
`local://`.

The order still matters, **token first, then file**, but not for the reason
stated here until 2026-09-07. `registry init` touches neither network nor
token: it checks the locator scheme and stops with exit 2 for anything
other than `local://`, before connecting. The write token is needed only
on the first `publish`. Forgetting it therefore produces a git-push
failure, not a network error.

| # | Who | Action | Result |
|---|---|---|---|
| 1 | Registry operator | Empty project `<gruppe>/skill-registry` on `git.example.com` | Empty repository, no README |
| 2 | Registry operator | Project Access Token, Maintainer, `write_repository`, set expiration | Part B, step 2 |
| 3 | Registry operator | Write register row **before** using the token | `OPS/token-register.md` |
| 4 | Registry operator | `registry init --registry local://…`, then `git push --mirror` to the GitLab project, then check the default branch | Structure is in the repository, see part B step 4 |
| 5 | Author | `pack` + `sign` with their own key | `.skb` and `.author.sig` |
| 6 | Publisher | `publish` (admit) | `transport=git` |
| 7 | Approver | `publish --attest --level green` with a **different** key | AC-2 |
| 8 | Consumer, second machine | Own read token from part A, **no** `.priv` on this machine | AC-5 |
| 9 | Consumer | `pull --install --trust-mode` | Five gates, `.m3c-provenance.json` and `.skillctl-attest.json` |
| 10 | Consumer | Remove the `signers:` entry and repeat the same pull | `gate 4`, exit **13**, nothing installed (AC-3) |
| 11 | Everyone | Write evidence block | AC-7, see scenario 02 tutorial |

Step 10 is the most important row. A run showing only success demonstrates
that the chain **lets through**, not that it **holds**. Since FR-0122 the
exit is 13 rather than 1; expecting 1 means checking against an older state.

Three principals, three machines (P3). Two principals on the same machine
are a dry run and must be recorded as such, not as D-8.

## Windows

Since `skillctl token set` became available, Windows is equivalent: the
token is encrypted with DPAPI per user account, not stored in the process
environment. Previously the environment variable was the only option there:
a write-capable plaintext token inherited by every child process. Until
2026-09-06 this page therefore recommended operating a registry only from
macOS or Linux. That recommendation is obsolete.

The read path always supported protected storage; what was missing was a
way to populate it. That is the kind of gap that looks complete from both sides.

## What this routine does not solve

**Expiration warnings.** GitLab gives no advance warning, and `skillctl`
does not know the expiration date: it is not encoded in a token. Hence the
register in part C, and why that row matters more than it appears to.

**Revocation.** `skillctl token rm` removes the local copy, which is hygiene.
To actually stop a token, revoke it in GitLab. This acts immediately,
without action by the affected machine.

## Related runbooks

| Runbook | Purpose |
|---|---|
| [Incident Response](ops-incident-response.en.md) | A key or registry is compromised |
| [Registry backup and restore](ops-registry-backup-restore.en.md) | Backup per backend, with restoration rehearsal |
| [Monitoring and alerting](ops-monitoring.en.md) | What is observable today and what is not |
