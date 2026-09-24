# Linux probe fixtures (SPEC-0471 TF06-R3)

## Source class

Every file under this directory is **transcribed from a real host and sanitized**, with one named
exception below. Nothing here was invented, and nothing here is a live capture.

Most of it came off one trial host on 2026-09-23 through read-only commands, and then went through
the substitutions listed below. Three files came off a **second real host on the same day**, an
Ubuntu 22.04 bastion where `docker` is installed as a **snap** (it answers only at
`/snap/bin/docker`) and where the daemon **socket refuses an unprivileged caller** because the
account is not in the group `docker`. Those three are
`containers/docker-version-snap.txt`, `containers/docker-ps-socket-denied.stderr.txt` and
`containers/docker-info-socket-denied.stderr.txt`; they carry `"host": "ubuntu-22.04-bastion"` in
`commands.json` and are byte for byte what the host printed, with nothing to substitute (no account
name, no host name and no address occurs in them). They are the two shapes the trial host could not
produce, and the first of them is why the runner search path now includes `/snap/bin`.

Two further files came off a **third real host**, an Ubuntu 22.04 bastion read during an **elevated**
run on the same day: `systemd/systemctl-show-template.stderr.txt` and
`systemd/systemctl-show-batch-aborted.txt`. They carry `"host": "ubuntu-22.04-bastion-elevated"` in
`commands.json`. The first is that host's stderr line, byte for byte. The second is the **one
composed file in this tree**: its SHAPE was measured on that host (a `systemctl show` call for
several units answers for the units before a name the manager refuses, prints nothing for the names
after it, and exits 1), its BYTES are two measured property blocks of the trial host, because the
bastion's property values were never transcribed and the probe asks for a different property set
than the reproduction did. Its `commands.json` entry says which half is which, and it is the only
file here whose bytes are not a host's.

That host carries 180 unit files, 33 of them templates, and it is where the batch abort cost one
capture the runtime state of 47 units.

The two hosts of the first two paragraphs were read as an ordinary, unprivileged user. No command elevated, wrote, installed,
started or stopped anything (playbook L2). That is why several fixtures are refusals rather than
data, and that is the point: the refusals are the shapes the probes have to survive.

Host class, so a parser author knows what the fixtures are valid for:

| Property | Trial host (all fixtures but three) | Bastion (the three named above) |
|---|---|---|
| Distribution | Ubuntu 24.04.1 LTS | Ubuntu 22.04 LTS |
| Kernel release | 6.17.0-35-generic | not recorded |
| Architecture | amd64 | amd64 |
| Privilege of the capture | unprivileged account, member of the groups `sudo` and `docker` | unprivileged account, NOT in the group `docker` |
| Container runtime | docker from the distribution package | docker from a snap, at `/snap/bin/docker` |
| Scale | 1879 dpkg packages, 516 unit files, 51 listeners, 113 mount points, 20 running containers | not measured: the socket refused every listing |

## Tool versions

A parser is only valid for the versions it was measured against (playbook L7). These are the
versions that produced the fixtures:

| Tool | Version | Fixture |
|---|---|---|
| `dpkg-query` | 1.22.6 (amd64) | `packages/dpkg-query-version.txt` |
| `apt-mark` | apt 2.7.14 (amd64) | `packages/apt-mark-version.txt` |
| `snap` / `snapd` | 2.76.3 | `packages/snap-version.txt` |
| `getent` | Ubuntu GLIBC 2.39-0ubuntu8.9 | `users/getent-version.txt` |
| `id` | GNU coreutils 9.4 | `users/id-version.txt` |
| `sshd` | OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 | `ssh/sshd-version.stderr.txt` |
| `systemctl` | systemd 255 (255.4-1ubuntu8.17) | `systemd/systemctl-version.txt` |
| `ss` | iproute2-6.1.0 | `network.listeners/ss-version.txt` |
| `ufw` | 0.36.2 | `firewall/ufw-version.txt` |
| `nft` | nftables v1.0.9 | `firewall/nft-version.txt` |
| `findmnt` | util-linux 2.39.3 | `mounts/findmnt-version.txt` |
| `docker` (trial host, deb) | 27.5.1, build 9f9e405 | `containers/docker-version.txt` |
| `docker` (bastion, snap) | 29.8.0, build 88096ef | `containers/docker-version-snap.txt` |
| `podman` | not installed | `honest-status/tool-missing-command-v-podman.txt` |
| `flatpak` | not installed | not fixtured, `command -v` behaves like podman |

## Environment of every capture

`LC_ALL=C`, with `LANG` and `LANGUAGE` removed. That is the environment `probe.ExecRunner` builds
(the variable allowlist plus `LC_ALL=C` and `TZ=UTC0`), so the fixtures show what a probe actually
receives. One fixture deliberately breaks the rule and says so in its entry:
`packages/snap-list-localized.txt` was taken with `LANG=de_DE.UTF-8` inherited, because `snap list`
translates its header words and re-computes its column widths. Two fixtures of the same command at
the same moment, different bytes. A parser that keys on header text or on fixed column offsets is
wrong, and this pair is how a test proves it.

## commands.json

`commands.json` is the machine readable index. One entry per fixture:

```
path                   fixture path relative to this directory
probe                  probe id the fixture belongs to (null for the cross cutting ones)
host                   id of the host class in other_host_classes; absent means the host_class at the top
source_class           present only where a fixture is not plain transcribed host output, and says what it is
command                argv exactly as it was run, executable first, no shell; null for a composed fixture
probe_command          argv the probe issues, where it differs from the one above; absent when they are the same
stream                 stdout or stderr: which stream the file holds; "n/a" for a composed fixture
exit_code              the exit code of that run; null for a composed fixture
expected_probe_status  the honest status the probe should report for this input; null where the probe never
                       issues this call, so the fixture is evidence about the tool and not an input
transcribed_lines      lines in the fixture
source_lines           lines in the untouched host output (differs where a subset was kept)
note                   what the fixture is for, and the trap it carries
```

Every fixture in this tree has an entry, and every entry names a file that exists.
`TestCommandsIndexCoversEveryFixture` in the package checks both directions, and it was shown to
fail on a planted file before it was believed: provenance that drifts from the tree is worse than
no provenance, because a fixture with no entry has no recorded argv.

`command` stays what was run on the host: it is a record of a measurement and is never edited to
match the code. Three fixtures were taken with an argv the probes do not issue (`findmnt --json`
without the column selection, and `sshd` through its absolute path), and those entries carry
`probe_command` beside it. The tests script the fake runner under `probe_command` where it exists
and under `command` otherwise, so a probe that changes its call fails a test instead of passing
quietly.

The fixtures themselves carry no header: a parser has to read them byte for byte as the tool
produced them, so provenance lives here and in `commands.json` instead of in the files. Five
fixtures are zero bytes long on purpose; they are the genuinely empty results, and their exit codes
(0, 1 and 2, all three occur) are in `commands.json`.

## Sanitization rules

Applied to every file. The rule is: change identity, keep shape. Column counts, field separators,
record order, padding widths, exit codes, streams and message wording are untouched.

| Real value | Replacement |
|---|---|
| the interactive account (uid 1000, gid 1000) | `alice`, home `/home/alice` |
| its GECOS full name | `Alice Example` |
| the service account (uid 1001, gid 1001) | `deploy`, home `/home/deploy` |
| a locally built daemon seen in the `ss` process column | `svc-app-exporte` (15 characters, so the comm truncation stays visible) |
| the host name | `host-a`, in FQDN position `host-a.example` |
| the one routable IPv4 in the material (a container registry) | `203.0.113.10` |
| container ids (64 hex) | synthetic 64 hex, one per row, equal values stay equal |
| an image digest (`sha256:` plus 64 hex) | one synthetic 64 hex, shared by the two rows that shared it |
| overlay2 layer ids and their `l/` short link names | synthetic, same lengths, one per distinct original |
| docker network namespace ids (12 hex) | synthetic 12 hex |
| registry organisation and product names in image references | `example/` plus a generic component name |
| container names built from product names | `app-*` and `svc-app-*` |
| a self-hosted runner unit name | `actions.runner.alice-m3c-tools.host-a.service`, padded back to the original column width |

IPv6: the rule is `2001:db8::`. No routable IPv6 address appears in the material of the sets above,
so none of them needed an IPv6 substitution; the routes fixtures of T-03b did need one and their own
section records it.

### The address rule (binding, machine-checked)

No fixture of this tree carries any part of a real address: not a prefix, not a host octet, and not a
vendor default pool that a real host happens to use today. The rule is mechanical on purpose,
because "a docker default pool names no site" is a judgement, and a judgement does not survive the
next author.

Every address literal in the tree therefore lies in one of these spaces:

| Space | Why it is allowed |
|---|---|
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737, reserved for documentation |
| `100.64.0.0/10` | RFC 6598 shared address space: the synthetic container networks of the routes fixtures. A bridge route is a `/16` on both hosts and no documentation range holds one, so the shape needs space RFC 5737 does not have |
| `2001:db8::/32` | RFC 3849, the IPv6 documentation prefix |
| `127.0.0.0/8`, `0.0.0.0`, `::`, `::1` | loopback and the unspecified address: a resolver at `127.0.0.53` and a listener on `0.0.0.0` are the substance of the fixture, not an identity |
| `169.254.0.0/16`, `fe80::/10` | link-local: the kernel derives them, no site chooses them |
| `224.0.0.0/4`, `ff00::/8` | IANA multicast |

`TestFixturesCarryNoRealAddress` in `testdataindex_test.go` walks the whole tree, this file included,
and fails on any other address. It is an allowlist and not a list of the real values, for two
reasons. Writing the addresses of the two hosts into a test would publish exactly what the
sanitization removes (playbook section 1 rule 8). And an allowlist is the stronger check: an address
pasted from ANY host fails it, not only one out of `10/8`, `172.16/12`, `192.168/16` or the
unique-local IPv6 range. The test measures itself first: it asserts that the check REJECTS planted
private-range addresses (none of them on any host of this project) and ACCEPTS the documented ones,
so "no hit" is a measurement and not an empty grep.

One literal is exempt, by exact string in one named file, because it only looks like an address: the
four-number version of one package in `packages/dpkg-query-w.txt`. A real address in that same file
still fails. This file names the banned ranges in their short form (`10/8`, `172.16/12`,
`192.168/16`) and the unique-local IPv6 range by name, so that the prose the rule lives in does not
have to be exempt from it.

What the check cannot do: it cannot tell a documentation address that was chosen freely from one that
kept a real host octet, because both lie in the allowed space. That half is a rule for the author and
it is this. When a real address is replaced, the HOST part is renumbered together with the prefix.
The octets a prefix or an allocator forces are not identity and stay: the zero host part of a network
address, the all-ones broadcast, and the first address of a network that an allocator gives itself
(each of the seven container networks of host A, six `br-*` bridges and `docker0`, carries its bridge
on the first address of that network, which is what the allocator does and not something the site
chose).

Never collected, and therefore absent by construction: private key material, public key bodies and
fingerprints, `authorized_keys` content, password hashes, tokens, and the contents of any file the
account was not allowed to read. `/etc/shadow` was not touched at all (playbook L4).

Two fixtures are shortened rather than substituted: `users/getent-version.txt` and
`users/id-version.txt` keep only the first line. The dropped lines are GPL boilerplate that names
the upstream authors, and a real person's name has no business in a fixture. The first line is the
line a version parser reads.

### What was deliberately NOT changed

- `127.0.0.1`, `127.0.0.53`, `127.0.0.54`, `0.0.0.0`, `::`, `::1`, `*`. These are the substance of
  the listener probe: a listener on `0.0.0.0` or `::` is exposure, one on loopback is not. Rewriting
  them would destroy the only fact the fixture carries.
- Port numbers. Same reason, and they identify no one.
- Uid and gid 1000 and 1001, group ids, file modes, sizes and timestamps.
- Volatile values: `pid=2698` in the `ss` line, `Up 2 weeks (healthy)` in `docker ps`, the
  `start_time`, `stop_time`, `pid`, `code` and `status` fields inside a systemd `ExecStart`, and
  nsfs inode numbers. They stay so that the normalization rule set (playbook L8) has something real
  to prove itself against.
- Public image names (`grafana/grafana`, `moby/buildkit`, `kindest/node`, `gitlab/gitlab-ce`,
  `confluentinc/cp-kafka`) and public package names. They name software, not a person or a site.

### Verification

After writing, the tree was searched for the real account name, the real full name, the real host
name and the one routable address that appeared in the material. No hit. `bash tools/boundary-gate.sh`
and `./scripts/check-no-real-names.sh` are green. The originals are not repeated here, because
writing them down would undo the substitution; whoever repeats the check fills them in from the
trial host:

```bash
grep -rniE "$REAL_ACCOUNT|$REAL_HOSTNAME|$REAL_IPV4" \
  pkg/skillctl/trustfreeze/platform/linux/testdata/
```

## Fixtures per probe

### linux.packages

| Fixture | What it shows |
|---|---|
| `packages/dpkg-query-w.txt` | 51 of 1879 packages in the host's order, both architectures (`all`, `amd64`), both status abbreviations (`ii `, `rc `), epoch versions, multiarch names such as `zlib1g:amd64`. The trailing space of the three character status field is real. |
| `packages/dpkg-query-w-unknown.stderr.txt` | named package absent: stderr diagnostic, exit 1 |
| `packages/apt-mark-showmanual.txt` | all 82 manually installed packages, one per line |
| `packages/snap-list.txt` | 24 snaps under `LC_ALL=C` |
| `packages/snap-list-localized.txt` | the same call with `LANG` inherited: other header words, other column widths |
| `packages/dpkg-query-version.txt`, `apt-mark-version.txt`, `snap-version.txt` | tool versions |

### linux.users

| Fixture | What it shows |
|---|---|
| `users/getent-passwd.txt` | all 53 accounts, colon separated, including empty GECOS fields, GECOS fields with trailing commas, and `nologin` or `false` shells |
| `users/getent-group.txt` | all 81 groups, including empty member lists and multi member lists |
| `users/getent-group-sudo-docker.txt` | two keys in one call, the privilege relevant pair |
| `users/id.txt` | the capturing account: `sudo` and `docker` membership, two privilege capabilities from one line |
| `users/id-service-account.txt` | an account with no supplementary groups |
| `honest-status/empty-result-getent-unknown-user.txt` | unknown key: empty stdout, exit 2 |
| `users/getent-version.txt`, `users/id-version.txt` | tool versions, first line |

### linux.sudo

| Fixture | What it shows |
|---|---|
| `sudo/ls-la-etc-sudoers-d.txt` | the drop-in directory is 0755, so names, modes, owners and sizes are observable, and one drop-in is called `alice-nopasswd` |
| `sudo/stat-sudoers.txt` | modes and owners of `/etc/sudoers`, the directory and both drop-ins |
| `sudo/cat-etc-sudoers.stderr.txt` | 0440 root:root: `permission_denied`, exit 1, stdout empty |
| `sudo/cat-etc-sudoers-d-entry.stderr.txt` | same for the drop-in whose name announces a NOPASSWD rule |

The honest result for this probe on this host is a `permission_denied` with the structure still
recorded: two rule files exist, one of them is named after a user and is 29 bytes long, and the rule
text is not observable. A silent empty rule list would be a lie.

### linux.ssh

| Fixture | What it shows |
|---|---|
| `ssh/sshd_config.txt` | the declared state, 3257 bytes, byte for byte, leading and trailing empty lines included. Carries `PasswordAuthentication yes` and `PermitEmptyPasswords yes`, an `Include /etc/ssh/sshd_config.d/*.conf`, a tab separated `AuthorizedKeysFile` comment and a commented `Match User` block |
| `ssh/ls-la-etc-ssh.txt` | nine `sshd_config.backup-*` files and one `.ucf-dist` beside the active file, plus the host key files whose contents were never read |
| `ssh/ls-la-sshd-config-d.txt` | the include directory is genuinely empty: `captured` with an empty list |
| `ssh/sshd-T-unprivileged.stderr.txt` | the effective state is not observable unprivileged: `sshd: no hostkeys available -- exiting.`, exit 1, stdout empty |
| `ssh/sshd-version.stderr.txt` | `sshd -V` writes to STDERR and exits 0 |

Declared stays declared (playbook L3). This host cannot produce an `observed` SSH state at all.

### linux.systemd

| Fixture | What it shows |
|---|---|
| `systemd/systemctl-list-unit-files.txt` | 55 of 516 unit files in the host's order, all nine state values that occur here, and every unit type. Column two begins at byte 79 |
| `systemd/systemctl-show-enabled-running.txt` | enabled and running |
| `systemd/systemctl-show-disabled.txt` | disabled and dead, `ConditionResult=no` |
| `systemd/systemctl-show-local-unit.txt` | a locally added unit under `/etc/systemd/system` running as a human account |
| `systemd/systemctl-show-unknown-unit.txt` | a unit that does not exist: exit 0, all properties present and empty, `LoadState=not-found` |
| `honest-status/empty-result-systemctl-no-match.txt` | pattern matches nothing: empty stdout, exit 1 |
| `systemd/systemctl-show-template.stderr.txt` | a TEMPLATE unit name refused, from the elevated Ubuntu 22.04 bastion: one stderr line, exit 1 |
| `systemd/systemctl-show-batch-aborted.txt` | the stdout half of that abort: the blocks that arrived before the refused name, nothing after it. Composed, see above |
| `systemd/systemctl-version.txt` | version plus the feature flag line |

Four traps live here. `systemctl show` returns the properties in systemd's order, not in the order
asked for, and it answers a question about a nonexistent unit with exit 0. A TEMPLATE unit
(`getty@.service`, an empty instance part) is not a nonexistent unit and not an unknown one: the
call is refused outright. And that refusal is not local to the bad name; the call STOPS there, so
every name after it in the same argument vector goes unanswered. Batching a hundred units into
calls of forty therefore loses a whole batch per template. `linux.systemd` reads the template from
the name grammar and never asks about one, and asks again, one name at a time, for whatever an
aborted call left unanswered.

### linux.network.listeners

| Fixture | What it shows |
|---|---|
| `network.listeners/ss-H-lntup.txt` | all 51 listeners, UDP and TCP, `0.0.0.0`, `127.0.0.1`, `127.0.0.53%lo`, `[::]`, `[::1]` and `*`, with variable column count |
| `honest-status/empty-result-ss-no-match.txt` | filter matches nothing: empty, exit 0 |
| `network.listeners/ss-version.txt` | tool version |

The decisive property: unprivileged, `ss -p` fills the `users:((...))` column only for the caller's
own processes. Exactly one of the 51 rows has seven fields, the other 50 have six. The honest status
is `partial` with a diagnostic naming the missing owner information, never `captured`.

### linux.firewall

| Fixture | What it shows |
|---|---|
| `firewall/ufw-status.stderr.txt` | `ERROR: You need to be root to run this script`, exit 1 |
| `firewall/nft-list-ruleset.stderr.txt` | two stderr lines, cause first, exit 1 |
| `firewall/nft-json-list-ruleset.stderr.txt` | the `--json` form fails identically and emits no JSON, so the exit code has to be checked before decoding |
| `firewall/ufw-version.txt`, `firewall/nft-version.txt` | tool versions |

Both tools are installed. `unavailable` would be false here; the truthful status is
`permission_denied`, and the firewall state of this host is simply not knowable from an
unprivileged capture.

### linux.mounts

| Fixture | What it shows |
|---|---|
| `mounts/findmnt-json.json` | 25 of 113 mount points as a pruned subtree, with `findmnt`'s own formatting: three space indentation, the `},{` sibling form, key order `target, source, fstype, options, children` |
| `mounts/findmnt-version.txt` | tool version |

The pruning tool round-tripped the untouched host file byte for byte before it removed anything, so
the formatting in the fixture is the tool's, not a re-serialization. Kept on purpose: an `autofs`
mount and the `binfmt_misc` mount nested under it at the same target path, `nsfs` sources of the
shape `nsfs[net:[4026531833]]`, a `tmpfs` at `/run/user/1000` with `uid=` and `gid=` options, a
`fuse.portal` and a `fuse.gvfsd-fuse` mount, squashfs snap mounts on loop devices, a second block
device at `/home`, and two `overlay` mounts whose `options` carry a twelve element and a four
element `lowerdir` chain.

### linux.containers

| Fixture | What it shows |
|---|---|
| `containers/docker-ps.txt` | 20 running containers, six tab separated fields, including an empty `Ports` field, port ranges, `0.0.0.0` and `[::]` and `:::` publishings, loopback-only publishings, and an image reference pinned by digest |
| `containers/docker-info.txt` | one line, ten tab separated fields, daemon version, storage driver, counts and root directory |
| `containers/docker-ps-empty.txt` | runtime present, no matching container: empty, exit 0 |
| `containers/docker-daemon-unreachable.stderr.txt` | client present, daemon unreachable, exit 1 |
| `containers/docker-version.txt` | client version of the deb package on the trial host |
| `containers/docker-version-snap.txt` | client version of a docker installed as a snap: the binary lives at `/snap/bin/docker`, which the four classic system directories do not contain |
| `containers/docker-ps-socket-denied.stderr.txt` | binary present, socket refused: `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock`, exit 1, stdout empty |
| `containers/docker-info-socket-denied.stderr.txt` | the same refusal from the info call, with an empty line in front of it, so a first-line reader sees nothing and the classification has to read the whole stream |

A format string trap that cost a round of collection: `docker ps --format` expands a literal
backslash-t into a tab, and `docker info --format` does not. The info fixture was therefore taken
with `{{"\t"}}`, a Go template string literal, and `commands.json` records both argv forms exactly.

## Honest status classes

Each class the parsers must be tested against, and the fixture that carries it:

| Class | Fixture | Shape |
|---|---|---|
| tool missing | `honest-status/tool-missing-command-v-podman.txt` | `command -v podman`: empty output, exit 1 |
| tool missing, shell variant | `honest-status/tool-missing-shell-127.stderr.txt` | `bash: line 1: ...: command not found`, exit 127 |
| permission refusal, config file | `sudo/cat-etc-sudoers.stderr.txt` | one stderr line, exit 1 |
| permission refusal, effective state | `ssh/sshd-T-unprivileged.stderr.txt` | one stderr line, exit 1 |
| permission refusal, firewall | `firewall/ufw-status.stderr.txt`, `firewall/nft-list-ruleset.stderr.txt` | one and two stderr lines, exit 1 |
| permission refusal, container socket | `containers/docker-ps-socket-denied.stderr.txt`, `containers/docker-info-socket-denied.stderr.txt` | one stderr line, exit 1; the info variant leads with an empty line |
| partial, privilege dependent column | `network.listeners/ss-H-lntup.txt` | 1 of 51 rows carries the owner column |
| empty result, exit 0 | `containers/docker-ps-empty.txt`, `honest-status/empty-result-ss-no-match.txt` | zero bytes |
| empty result, exit 1 | `honest-status/empty-result-systemctl-no-match.txt` | zero bytes |
| empty result, exit 2 | `honest-status/empty-result-getent-unknown-user.txt` | zero bytes |
| object absent, exit 0 | `systemd/systemctl-show-unknown-unit.txt` | full property set, `LoadState=not-found` |
| object absent, exit 1 | `packages/dpkg-query-w-unknown.stderr.txt` | stderr diagnostic |

The shell variant is recorded to be dismissed, not to be parsed: `probe.ExecRunner` resolves the
executable through `LookPath` and returns `tool_missing` before any process starts, so it never sees
exit 127. A real 127 from a child process means something else and must not be read as absence.

## What this host could not show

Honest gaps in the fixture set, so nobody builds a test on a shape that was never measured:

- **A docker socket the caller may not open.** No longer a gap, and kept here to say where it was
  closed. The trial host cannot produce it (its account is in the group `docker`); the bastion can,
  and `containers/docker-ps-socket-denied.stderr.txt` plus
  `containers/docker-info-socket-denied.stderr.txt` are that host's two refusals. The
  unreachable-daemon shape in `containers/docker-daemon-unreachable.stderr.txt` stays a different
  message, forced with `DOCKER_HOST` pointing at a path that does not exist.
- **podman.** Not installed, so only its absence is fixtured, never its output.
- **An active firewall ruleset.** Both backends refuse unprivileged; no `nft --json` document and no
  `ufw status` table exist in this set.
- **The effective sshd state.** `sshd -T` never succeeded, so there is no `observed` SSH fixture.
- **Sudoers rule text.** Only the structure around the files, never a rule.
- **The `docker inspect` answer.** The container probe asks `docker inspect --format ...` for the
  restart policy and the privileged flag, and that call was never transcribed from the trial host.
  `containers_test.go` builds the answer by hand from the ids of `containers/docker-ps.txt` and says
  so in the test. Until a run on a Linux host records it, the parser of that call is fixture-tested
  against a constructed input, not against a measured one.
- **A snap-less or docker-less host.** Neither measured machine is one, so the "tool not found
  anywhere we looked" path of `linux.packages` and `linux.containers` is covered by the absence of
  podman and flatpak only. That path reports `unavailable` and names the searched directories; it
  never reports `not_applicable`, because a failed lookup cannot tell a host without a runtime from
  a runtime this build did not look in the right place for.
- **A container runtime that is neither docker nor podman.** `containerd` and `crio` are not read at
  all by this build. A host that runs only one of them gets the same `unavailable` with the
  directories named, which is the honest answer and not the complete one.

## Fixtures of `linux.network.routes` and `linux.dns` (T-03b)

Added with the two probes of T-03b. They live under `routes/` and `dns/`. Unlike the sets above,
where a second host supplied the shapes the first one could not produce, here **the same commands
were run on both hosts on purpose**: the two Ubuntu releases ship different versions of `ip` and of
`resolvectl`, the two versions print differently, and that difference is what the parsers had to be
measured against. Everything here was read on **2026-09-24** through read-only commands, as an
ordinary unprivileged account. Nothing was written, started, stopped or elevated on either host.

These fixtures **are listed in `commands.json`**, folded in from the table below. Host B carries
`"host": "ubuntu-22.04-bastion"`, the host class the container fixtures of T-03 already used: the
same machine, confirmed read-only on 2026-09-24 by `command -v docker` answering `/snap/bin/docker`
and `id -nG` not naming the group `docker`, which is exactly what that host class records. Host A
carries no `host` key, because it is the `host_class` at the top of the file.

### Host classes

| Property | Host A (fixtures without a suffix) | Host B (fixtures with `-2204`) |
|---|---|---|
| Distribution | Ubuntu 24.04.1 LTS | Ubuntu 22.04.5 LTS |
| Role | the trial host of the T-03 fixtures above | the bastion, ngrok and MinIO present |
| Kernel release | 6.17.0-35-generic | not recorded |
| Architecture | amd64 | amd64 |
| Privilege of the capture | unprivileged account, no elevation | unprivileged account, no elevation |
| Scale, routes | 9 IPv4 and 24 IPv6 routes over 27 interfaces | 4 IPv4 and 2 IPv6 routes over 5 interfaces |
| Scale, resolver | 26 link blocks, 1 of them resolving | 4 link blocks, 1 of them resolving |

The four scale rows are counts, so they carry a date: they were re-measured on **2026-09-24** with
`ip -o link show | wc -l`, `ip -j route show`, `ip -6 -j route show` and
`resolvectl status --no-pager | grep -c '^Link '` on both hosts, and the table above is that
measurement. Host A's resolver row said 27 when the fixture was cut and answers 26 on the
re-measurement of the same day: container veths come and go, so a later count that differs from this
table is volatility of that host and not drift of these fixtures. A count in this file is never a
claim about a host on any other day.

### Tool versions

| Tool | Host A | Host B | Fixture |
|---|---|---|---|
| `ip` (iproute2) | `iproute2-6.1.0, libbpf 1.3.0` | `iproute2-5.15.0, libbpf 0.5.0` | `routes/ip-version.txt`, `routes/ip-version-2204.txt` |
| `resolvectl` (systemd) | `systemd 255 (255.4-1ubuntu8.17)` | `systemd 249 (249.11-0ubuntu3.22)` | `dns/resolvectl-version.txt`, `dns/resolvectl-version-2204.txt` |

### The fixtures

| Fixture | Command | Stream | Exit | Host |
|---|---|---|---|---|
| `routes/ip-j-route-show.json` | `ip -j route show` | stdout | 0 | A |
| `routes/ip-6-j-route-show.json` | `ip -6 -j route show` | stdout | 0 | A |
| `routes/ip-j-addr-show.json` | `ip -j addr show` | stdout | 0 | A |
| `routes/ip-j-route-show-2204.json` | `ip -j route show` | stdout | 0 | B |
| `routes/ip-6-j-route-show-2204.json` | `ip -6 -j route show` | stdout | 0 | B |
| `routes/ip-j-addr-show-2204.json` | `ip -j addr show` | stdout | 0 | B |
| `routes/ip-j-route-show-empty.json` | `ip -j route show 203.0.113.0/24` | stdout | 0 | A and B, identical |
| `routes/ip-6-j-route-show-aborted.json` | `ip -6 -j route show table 999` | stdout | 2 | A and B, identical |
| `routes/ip-6-j-route-show-aborted.stderr.txt` | the same call | stderr | 2 | A and B, identical |
| `routes/ip-route-show-nosuchdev.stderr.txt` | `ip -j route show dev nosuchdev` | stderr | 1 | A |
| `dns/resolvectl-status.txt` | `resolvectl status --no-pager` | stdout | 0 | A |
| `dns/resolvectl-status-2204.txt` | `resolvectl status --no-pager` | stdout | 0 | B |
| `dns/resolvectl-json-unsupported.stderr.txt` | `resolvectl --json=short status` | stderr | 1 | B |
| `dns/resolv-conf-stub.txt` | `cat /etc/resolv.conf` | stdout | 0 | A and B, byte identical |
| `dns/resolv-conf-uplink.txt` | `cat /run/systemd/resolve/resolv.conf` | stdout | 0 | A |
| `dns/resolvectl-status-multilink.txt` | composed, see below | n/a | n/a | n/a |
| `dns/resolv-conf-static.txt` | composed, see below | n/a | n/a | n/a |

Three of them are subsets rather than whole outputs, with the original order kept:
`routes/ip-6-j-route-show.json` holds 5 of the 24 IPv6 routes (the one global-scope route plus four
link-local routes that share the destination and differ only in the device, which is the case the
artifact id has to survive), `routes/ip-j-addr-show.json` holds 6 of the interfaces, and
`dns/resolvectl-status.txt` holds the global block plus 4 of the link blocks. **No route was left
out**: host A's IPv4 fixture holds all 9 routes the host printed, in the printed order (the default
route, seven container bridge routes, the LAN route). An earlier version of this file said one route
had been dropped because no documentation range of its size was free; the fixture carried it all
along, unsanitized, and now carries it renumbered.

### The two composed fixtures

`dns/resolvectl-status-multilink.txt` and `dns/resolv-conf-static.txt` are **composed, not
measured**, and they are the only files under `routes/` and `dns/` whose bytes are not a host's. The
reason is named rather than hidden: neither host has a link with several DNS servers, a search
domain, a routing-only domain, DNSSEC on or DNSOverTLS on, and neither host is without
systemd-resolved, so those shapes could not be read anywhere. What IS measured about them is their
form: the labels are the labels the two hosts printed plus `DNS Domain`, and the alignment follows
the rule the measured output of systemd 255 exhibits (every label right-aligned to one
document-wide width). Values are documentation addresses and `.example` names throughout.

### What the two hosts could not show

- **A JSON form of `resolvectl status`.** There is none. Measured on both: systemd 249 refuses
  `--json=short` with `resolvectl: unrecognized option '--json=short'` and exit 1, and systemd 255
  ACCEPTS the flag, exits 0, and prints the same human text it prints without it. The probe
  therefore never sends the flag, and `dns_test.go` guards that.
- **A refusal of `ip route show`.** Reading the routing table needs no privileges, so neither host
  could produce one read-only. The `permission_denied` path of `linux.network.routes` is covered
  with a refused start at the runner, which is where the operating system reports it.
- **An unreadable `/etc/resolv.conf`.** The file is 0644 on both hosts. The refusal shape is real
  even so: `/run/systemd/resolve/netif` is `drwx------` and owned by `systemd-resolve` on host A, and
  an unprivileged read of a file under it answers `Permission denied` with exit 1. The probe's
  `permission_denied` path is covered with that error at the file reader.
- **A host without systemd-resolved.** Both hosts run it, so the file-only path is covered with a
  missing `resolvectl` at the runner, and the fixture for it is the absence of the tool.
- **A second routing table.** Only the main table was read, which is what `ip route show` answers
  for. A host with policy routing keeps rules and tables that no fixture here carries.

### Sanitization of these fixtures

Same rule as above: change identity, keep shape. The JSON stayed one compact line with the key
order iproute2 printed, and the resolvectl text kept its indentation byte for byte.

| Real value | Replacement |
|---|---|
| the LAN prefix, the gateway and the address of host A | `203.0.113.0/24`, gateway `203.0.113.254`, address `203.0.113.10` (the same address the container fixtures above already use for this host) |
| the LAN prefix, the gateway and the address of host B | `198.51.100.0/24`, gateway `198.51.100.254`, address `198.51.100.20` |
| the resolver of each host, which on both is its gateway | the gateway replacement of that host |
| the seven container bridge networks of host A (five `/16` and two `/24`, out of the default pools of docker, docker compose and kind) | `100.64.0.0/16`, `100.65.0.0/16`, `100.66.0.0/16`, `100.67.0.0/16`, `100.68.0.0/16`, `100.69.0.0/24`, `100.70.0.0/24`, each with the bridge on the first address of its network |
| the docker bridge network of host B | `100.64.0.0/16`, the same replacement host A's docker bridge got, because the two hosts really do carry the same network there and a fixture that hid that would be a different fact |
| the IPv6 network of one bridge (a unique-local prefix the runtime generated) | `2001:db8:1a2b:3c4d::/64` |
| the MAC address of a physical interface | `00:00:5e:00:53:xx`, the documentation range of RFC 7042 |
| a MAC address a container runtime generated | a synthetic address of the same class: docker's fixed `02:42` prefix where docker used one (the bridges of host A), a locally administered address where the runtime used one outside that prefix (`docker0` of host B) |
| an IPv6 link-local address | a synthetic address of the same form: where the real one is derived from a MAC (host A), the derivation over the replacement MAC; where it is a stable-privacy address (host B, RFC 7217, not MAC-derived), a synthetic address of the same length |
| docker bridge names (`br-` plus 12 hex of a network id) | synthetic 12 hex, same length |
| veth names (`veth` plus 7 hex) | synthetic 7 hex, same length |

Kept, deliberately, and why: `127.0.0.1`, `127.0.0.53`, `::1`, `fe80::/64`, `169.254.0.0/16` and the
port numbers. They are IANA-assigned or kernel-derived and they are the substance of the fixture (a
resolver at `127.0.0.53` is the stub, and that is the finding).

Nothing else is kept. An earlier version of this file kept the container bridge prefixes with the
argument that docker, docker compose and kind assign them out of documented default pools, so they
name a container network and not a site. The argument is true and the exception was still wrong: the
values stood in the fixtures exactly as both hosts carry them today, and a rule with a judgement in
it is not a rule (see "The address rule" above). The renumbering is visible in the bytes: the bridge
networks now come out of `100.64.0.0/10`, which no vendor assigns, so nobody reads them as a default
pool. The prefix LENGTHS, the device names, the record order, the key order, the flags and every
other column are the host's.

Interface names of physical devices (`enp5s0`, `enp2s0`, `eno2`, `wlo1`, `lo`, `docker0`) are the real
ones. They are bus positions and kernel defaults, they name no person, no site and no host, and the
`-2204` fixtures would stop being one host's output if they were renamed.

### Verification of these fixtures

Two checks, and what each one proves:

- `TestFixturesCarryNoRealAddress` (see "The address rule" above) walks the whole tree and refuses
  every address outside the documented spaces. Measured against the fixture bytes the T-03b reviewer
  read, it names 30 literals in 5 files; against the current bytes it names none. That measurement,
  and not a sentence, is what says the addresses are clean, and it repeats on every `go test`.
- The values a repository check cannot carry, because carrying them would publish them, were searched
  for by hand on **2026-09-24**: every interface name, every MAC address and every address of both
  hosts that the site or a runtime chose (the IANA-assigned loopback, unspecified and multicast values
  are excluded, they are the ones the fixtures keep on purpose). 88 values, **0 hits** in this tree.
  The search was shown to work: with two of those values appended to one file of a throwaway copy, the
  same search returns 1 hit. The procedure, to repeat it:

  ```bash
  # on each host, read-only:
  LC_ALL=C ip -o link show; LC_ALL=C ip -o addr show
  # keep the interface names, the MAC addresses and the addresses, drop loopback,
  # ::, 0.0.0.0 and multicast, write one value per line into /tmp/real-values.txt
  grep -rFf /tmp/real-values.txt pkg/skillctl/trustfreeze/platform/linux/testdata/
  # then append one of the values to a COPY of the tree and run the same grep,
  # so that "no hit" is a measurement and not an empty pattern file.
  ```

What the earlier version of this paragraph claimed without having it: "the tree was searched for
every real address of both hosts. No hit." Nothing in the repository could repeat that search, and
seven of the prefixes it should have found were in the fixtures. The test above is what replaces the
sentence.

## Fixtures of `linux.executables` and of the systemd dependency edges (T-03b)

They live under `executables/`, plus two files under `systemd/` that belong to `linux.systemd`
because its show property list now carries the five dependency properties. Their own prose, with
what each fixture is for and the trap it carries, is `executables/README.md`; that file is the
measurement record and is not repeated here. What belongs here is the part this file owns.

All of it was read on **2026-09-24** through read-only commands, as an ordinary unprivileged
account. Nothing was written, started, stopped or elevated on either host. Fixtures without a suffix
came off the trial host (the `host_class` at the top of `commands.json`); fixtures with `-2204` came
off the bastion, `"host": "ubuntu-22.04-bastion"`, the same machine the container fixtures of T-03
used.

| Tool | Trial host | Bastion | Fixture |
|---|---|---|---|
| `dpkg` | 1.22.6 (amd64) | 1.21.1 (amd64) | `executables/dpkg-version.txt`, `executables/dpkg-version-2204.txt` |
| `stat` (GNU coreutils) | 9.4 | 8.32 | `executables/stat-version.txt`, `executables/stat-version-2204.txt` |
| `systemctl` | systemd 255 (255.4-1ubuntu8.17) | systemd 249 (249.11-0ubuntu3.22) | `systemd/systemctl-version.txt` (trial host); no fixture for the bastion, the version was read there and written down here |
| `ss` | iproute2-6.1.0 | iproute2-5.15.0 | `network.listeners/ss-version.txt` (trial host); no fixture for the bastion, same |

The two bastion versions without a fixture were read on that host on 2026-09-24 with
`LC_ALL=C systemctl --version` and `LC_ALL=C ss -V`, which answered `systemd 249
(249.11-0ubuntu3.22)` and `ss utility, iproute2-5.15.0`. They are written down rather than fixtured
because no parser of this package was measured against the bastion output of those two tools; the
`-2204` fixtures that DO exist are the ones a parser reads.

The bastion is the host this probe exists for, and it is the only one that carries both cases in one
call: a program under `/usr/local/bin` that **is** owned by a package (`mcli`, installed from a
`.deb`) and one that **no package owns** (`ngrok`). Both were measured, neither was staged.

### Four entries whose host argv is not recorded

`executables/systemctl-list-unit-files-subset.txt`, `executables/systemctl-list-unit-files-subset-2204.txt`,
`executables/stat-unit-programs.txt` and `executables/dpkg-search-unit-programs.txt` are in
`commands.json`, but their `command` is the argv the **probe** issues, taken from how
`executables_test.go` scripts the fake runner, and not from a record of the call that produced the
bytes. `executables/README.md` does not list these four in its argv table. Their notes say so in the
file itself rather than leaving a reader to assume a measurement. Closing that gap needs the fixture
author, not an edit here: an argv is the record of a measurement and is never derived from the code
it feeds.

