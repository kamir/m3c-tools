# Reference: secretctl, the life of a shared service secret

Who holds a shared service secret, whether each place holds the current value,
and whether a service still accepts it: `cmd/secretctl` (SPEC-0438) answers
those three questions and nothing else. Everything below was read from
`cmd/secretctl/main.go`, `registry.go`, `read.go`, `secret.go`,
`inventory.go` and `verify.go` at commit `bd00a6f` (the state PR #319 merges
into master) on 2026-09-16. Every command output and exit code quoted in this
page was measured against a binary built from exactly that state
(`go build ./cmd/secretctl`), offline; sentences that only restate the code
say so.

Audience: a developer or operator who has to run an inventory before a
rotation, or prove that a rotation finished. The build entry is in the
[Program-Index](../../program-index.md) once #319 has landed; the wider gates
around a change are on the
[developer getting-started page](getting-started.md).

Rolle: Entwickler · Sprache: EN · Stand: 2026-09-16

## The core rule in one sentence

**The tool reads and compares; it never prints a secret value.** In the code:
values travel as the type `Secret` (`cmd/secretctl/secret.go`), which renders
as `<redacted>` through `String`, `GoString`, `MarshalJSON` and `MarshalYAML`;
every report and comparison runs over `Fingerprint()`, and the only path to
the raw value is the deliberately conspicuous `Reveal()`. Measured: a planted
value (`super-test-value-123`) placed in a file holder appears in none of the
captured outputs of `inventory` and `verify`, while the same `grep` pattern
does find it in the source file it was planted in.

## Verbs and flags

The dispatch in `cmd/secretctl/main.go`:

| Verb | What it does | State |
|---|---|---|
| `inventory <name>` | who holds this secret, and does each hold the current value | built |
| `verify <name>` | ask the service, per holder, whether its value is accepted | built |
| `verify --old <name>` | expect refusal instead: the proof that a rotation finished | built |
| `new`, `stage`, `distribute`, `retire` | the writing half of SPEC-0438 | refused with exit `2`, "not built yet" |
| `help`, `-h`, `--help` | print usage | exit `0` |

One shared flag, wired by `registryFlag` in `main.go`:

| Flag | Meaning | Default |
|---|---|---|
| `--registry <path>` | path to the secret registry | `$SECRETCTL_REGISTRY`, else `~/.config/m3c/secrets.yaml` (`DefaultRegistryPath`, `registry.go`) |

**Flags go before the name.** Go's `flag` parsing stops at the first
positional argument, so `secretctl verify demo --old` prints the usage line
and exits `2` (measured); the working form is `secretctl verify --old demo`.

## Which verb, when

| You want to know | Run | Green means |
|---|---|---|
| who holds the secret, before touching anything | `inventory <name>` | every listed place carries the current value |
| whether the new value is live everywhere | `verify <name>` | every probed place is accepted |
| whether the rotation actually finished | `verify --old <name>` | every place carrying the old value is refused |

## The registry file

The registry holds locations, never values, which is what makes it checkable
into git (`cmd/secretctl/registry.go`). Schema string:
`m3c-secret-registry/v1`; the loader refuses any other. Shape, from the
structs in `registry.go`:

```yaml
schema: m3c-secret-registry/v1
secrets:
  - name: er1-api-key
    summary: what this secret is
    prefix: m3cer1_          # optional, SPEC-0438 §5
    source:                  # where the authoritative value lives
      kind: gcp-secret-manager
      project: my-project
      secret: er1-api-key
    roles:                   # what breaks when the value turns
      - id: service-clients
        was: authenticates service clients
        bei_rotation: clients need the new value at next start
    holders:                 # every place that carries a copy, named one by one
      - id: laptop-keychain
        kind: macos-keychain
        service: aims-core-er1
      - id: laptop-env
        kind: file
        path: ~/.m3c-tools.env
        key: ER1_API_KEY
    probe:                   # how to ask the service whether a value counts
      kind: http
      url: https://example.org/api/health
      header: X-API-KEY
      expect_ok: 200
      expect_revoked: 401
```

Holder kinds and their required fields (`Holder.validate`, `registry.go`):

| Kind | Required fields | How it is read (`read.go`) |
|---|---|---|
| `macos-keychain` | `service` | `security find-generic-password`, locally or over ssh (`host`) |
| `file` | `path`, `key` | `grep -m1 '^KEY='`, never `cat`: the whole file must not travel |
| `cloud-scheduler` | `project`, `region`, `job`, `header` | `gcloud scheduler jobs describe`, header out of the job definition |
| `docker` | `container`, `env` | `docker inspect` on the running container's environment |
| `cloud-run` | `project`, `region`, `service_name`, `env` | not read by value; the BOUND SECRET VERSION is reported instead (`BoundVersion`) |

`Validate` in `registry.go` refuses a registry that cannot carry a rotation:
a secret without holders, a secret without roles, a role missing `id`, `was`
or `bei_rotation`, duplicate secret or holder ids, and any holder whose id or
path reads as a collective (`*`, `alle`, `all `, `usw`, `...`): every place
is named individually, because a rotation fails at the copy nobody listed.

**Probes must use https.** `Probe.validate` (`registry.go`) rejects an
`http://` probe URL unless the host is `localhost`, `127.0.0.1` or `::1`,
because the probe puts the live value into a request header and plaintext
would repeat it on every verify. Measured against the built binary: a
registry with `url: http://example.com/api/health` makes `inventory` exit `1`
with

```
... probe url "http://example.com/api/health" would send the live value over plaintext http; use https (http is allowed only for localhost)
```

## Security properties, each with its source

Code reading, file and identifier named; the two marked lines were also
measured against the built binary:

- **No value in any output.** Type `Secret` with `<redacted>` renderers and
  greppable `Reveal()` (`secret.go`). Measured: planted-value grep over all
  captured outputs, see the core rule above.
- **Fingerprints, not values, are compared and printed.**
  PBKDF2-HMAC-SHA256, `600_000` iterations, public fixed salt
  `m3c-secretctl-fingerprint/v1`, first 12 hex characters
  (`Secret.Fingerprint`, `secret.go`). The salt is public by design so two
  machines derive the same tag; the work factor is the protection. Measured:
  two separate runs printed the same 12-hex fingerprint for the same value.
- **The probe follows no redirects.** `Probe.Ask` (`read.go`) sets
  `CheckRedirect` to return `http.ErrUseLastResponse`, so the credential
  header can neither travel to another host nor repeat over a downgraded
  scheme; the 30x itself is the answer.
- **The probe is in-process HTTP, not curl.** A value handed to curl as a
  header sits in that process argv for every `ps` to read; `Probe.Ask` keeps
  it inside the process (comment and code, `read.go`).
- **Remote arguments are shell-quoted.** ssh joins its arguments into one
  string for the remote login shell, so `capture` (`read.go`) quotes every
  remote argument via `shellQuote`/`shellQuoteRemote`; only the deliberate
  `$HOME/` prefix stays expandable.
- **File keys pass a whitelist before becoming a pattern.** `readFile`
  (`read.go`) refuses any key not matching `^[A-Za-z0-9_]+$`
  (`envKeyShape`) instead of escaping it into the `grep` pattern.
- **Unreachable is never reported as absent.** `ErrUnreachable` and
  `ErrAbsent` are distinct types (`read.go`); ssh's exit `255` marks
  transport failure, grep's `1`/`2` are real answers. An inventory with an
  unreachable place calls itself INCOMPLETE and exits `1`
  (`inventory.go`).

## Exit codes

Read from the `return` statements in `main.go`, `inventory.go` and
`verify.go`; every row was confirmed by at least one measured run:

| Code | Meaning |
|---|---|
| `0` | help; or every place is current (`inventory`); or every probed place answered as expected (`verify`) |
| `1` | a finding or an operational failure: registry missing or invalid, unknown secret name, `verify` without a configured probe, stale or valueless or unreachable places, a probe answer other than expected |
| `2` | usage: no verb, unknown verb, one of the unbuilt writing verbs, wrong argument count, unparseable flag |

Measured runs behind that table, 12 in total: `-h` exits `0`; five runs exit
`2` (no verb, unknown verb, `new`, `inventory` without a name, a flag placed
after the positional name); five runs exit `1` (missing registry file,
unknown secret name, a registry refused for its plaintext probe URL, `verify`
on an entry without a probe, a failed loopback probe); the offline inventory
run below exits `0`.

## Practice, measured offline

Both parts were run on 2026-09-16 against the binary built from `bd00a6f`,
with a local registry, a local file holder, and no network beyond loopback.
`gcloud` was kept off `PATH`, so the source read fails visibly; nothing was
asked of a real system and no real secret was involved.

### Part A: check a value

```bash
go build -o secretctl ./cmd/secretctl
./secretctl inventory --registry ./measure/reg.yaml demo
```

Measured output (the fingerprint is the real one for the planted test
value):

```
Geheimnis:  demo
            offline measurement entry, file holder only
Quelle:     NICHT LESBAR (source none-project/demo: exec: "gcloud": executable file not found in $PATH)
            Ohne die Quelle ist kein Abgleich moeglich; die Spalte Stand bleibt leer.
...
ORT         ART   MASCHINE  FINGERABDRUCK  STAND
laptop-env  file  lokal     f9448d60fde5   ?

1 Orte gefuehrt.
```

Exit code: `0`. Two things to read off this run: an unreadable source leaves
STAND at `?` and does not by itself fail the run, and the holder's value
surfaces only as a 12-hex fingerprint. With a readable source the STAND
column says `aktuell` or `veraltet`, and any `veraltet`, `fehlt` or
`unerreichbar` row turns the exit code to `1` (`inventory.go`; code reading,
the online path was not run here).

### Part B: probe a rotation

```bash
./secretctl verify --registry ./measure/reg.yaml --old demo-probe
```

Measured output, against a loopback probe URL with nothing listening:

```
Geheimnis:  demo-probe
Probe:      http://127.0.0.1:9/api/health, erwartet 401 (abgewiesen)

ORT         FINGERABDRUCK  ANTWORT  URTEIL
laptop-env  f9448d60fde5   n/a      PROBE FEHLGESCHLAGEN

0 Orte befragt, 1 nicht wie erwartet.
Solange ein alter Wert noch angenommen wird, hat die Rotation nichts bewirkt.
```

Exit code: `1`. Against a live service the ANTWORT column carries the HTTP
status per holder, and `--old` inverts the expectation to `expect_revoked`:
a rotation counts as finished only when every place still carrying the old
value is refused (`verify.go`; the live path is code reading, not measured
here).

And the refusal worth knowing before scripting around it, measured:
`verify` on an entry with no `probe:` block prints
`verify: "demo" has no probe; without one there is nothing to ask` and exits
`1`.

## Where the rest lives

- The spec: SPEC-0438 on the private maintenance plane, referenced by id
  (SPEC-0358: a public-plane file carries no path into the private one).
- The writing half (`new`, `stage`, `distribute`, `retire`) is deliberately
  not in this build; the verbs exist in the dispatch and refuse with exit `2`
  (`main.go`).
- The generated, printable form of this page:
  [Doku-Seite](../pages/entwickler-secretctl.html), gated by
  `scripts/check-docpages.sh`.
